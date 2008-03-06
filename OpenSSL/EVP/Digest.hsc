{- -*- haskell -*- -}

-- #prune

-- |An interface to message digest algorithms.

#include "HsOpenSSL.h"

module OpenSSL.EVP.Digest
    ( Digest
    , EVP_MD -- private
    , withMDPtr -- private

    , getDigestByName
    , getDigestNames

    , DigestCtx -- private
    , EVP_MD_CTX -- private
    , withDigestCtxPtr -- private

    , digestStrictly -- private
    , digestLazily   -- private

    , digest
    , digestBS
    , digestBS'
    , digestLBS

    , hmacBS
    )
    where

import           Control.Monad
import           Data.ByteString.Internal (createAndTrim)
import           Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign
import           Foreign.C
import           OpenSSL.Objects
import           OpenSSL.Utils


{- EVP_MD -------------------------------------------------------------------- -}

-- |@Digest@ is an opaque object that represents an algorithm of
-- message digest.
newtype Digest  = Digest (Ptr EVP_MD)
data    EVP_MD


foreign import ccall unsafe "EVP_get_digestbyname"
        _get_digestbyname :: CString -> IO (Ptr EVP_MD)


withMDPtr :: Digest -> (Ptr EVP_MD -> IO a) -> IO a
withMDPtr (Digest mdPtr) f = f mdPtr

-- |@'getDigestByName' name@ returns a message digest algorithm whose
-- name is @name@. If no algorithms are found, the result is
-- @Nothing@.
getDigestByName :: String -> IO (Maybe Digest)
getDigestByName name
    = withCString name $ \ namePtr ->
      do ptr <- _get_digestbyname namePtr
         if ptr == nullPtr then
             return Nothing
           else
             return $ Just $ Digest ptr

-- |@'getDigestNames'@ returns a list of name of message digest
-- algorithms.
getDigestNames :: IO [String]
getDigestNames = getObjNames MDMethodType True


{- EVP_MD_CTX ---------------------------------------------------------------- -}

newtype DigestCtx  = DigestCtx (ForeignPtr EVP_MD_CTX)
data    EVP_MD_CTX


foreign import ccall unsafe "EVP_MD_CTX_init"
        _ctx_init :: Ptr EVP_MD_CTX -> IO ()

foreign import ccall unsafe "&EVP_MD_CTX_cleanup"
        _ctx_cleanup :: FunPtr (Ptr EVP_MD_CTX -> IO ())


newCtx :: IO DigestCtx
newCtx = do ctx <- mallocForeignPtrBytes (#size EVP_MD_CTX)
            withForeignPtr ctx $ \ ctxPtr ->
                _ctx_init ctxPtr
            addForeignPtrFinalizer _ctx_cleanup ctx
            return $ DigestCtx ctx


withDigestCtxPtr :: DigestCtx -> (Ptr EVP_MD_CTX -> IO a) -> IO a
withDigestCtxPtr (DigestCtx ctx) = withForeignPtr ctx


{- digest -------------------------------------------------------------------- -}

foreign import ccall unsafe "EVP_DigestInit"
        _DigestInit :: Ptr EVP_MD_CTX -> Ptr EVP_MD -> IO Int

foreign import ccall unsafe "EVP_DigestUpdate"
        _DigestUpdate :: Ptr EVP_MD_CTX -> Ptr CChar -> CSize -> IO Int

foreign import ccall unsafe "EVP_DigestFinal"
        _DigestFinal :: Ptr EVP_MD_CTX -> Ptr CChar -> Ptr CUInt -> IO Int


digestInit :: Digest -> IO DigestCtx
digestInit (Digest md)
    = do ctx <- newCtx
         withDigestCtxPtr ctx $ \ ctxPtr ->
             _DigestInit ctxPtr md >>= failIf (/= 1)
         return ctx   


digestUpdateBS :: DigestCtx -> B8.ByteString -> IO ()
digestUpdateBS ctx bs
    = withDigestCtxPtr ctx $ \ ctxPtr ->
      unsafeUseAsCStringLen bs $ \ (buf, len) ->
      _DigestUpdate ctxPtr buf (fromIntegral len) >>= failIf (/= 1) >> return ()


digestFinal :: DigestCtx -> IO String
digestFinal ctx
    = withDigestCtxPtr ctx $ \ ctxPtr ->
      allocaArray (#const EVP_MAX_MD_SIZE) $ \ bufPtr ->
      alloca $ \ bufLenPtr ->
      do _DigestFinal ctxPtr bufPtr bufLenPtr >>= failIf (/= 1)
         bufLen <- liftM fromIntegral $ peek bufLenPtr
         peekCStringLen (bufPtr, bufLen)

digestFinalBS :: DigestCtx -> IO B8.ByteString
digestFinalBS ctx =
  withDigestCtxPtr ctx $ \ctxPtr ->
  createAndTrim (#const EVP_MAX_MD_SIZE) $ \bufPtr ->
  alloca $ \bufLenPtr ->
  do _DigestFinal ctxPtr (castPtr bufPtr) bufLenPtr >>= failIf (/= 1)
     liftM fromIntegral $ peek bufLenPtr


digestStrictly :: Digest -> B8.ByteString -> IO DigestCtx
digestStrictly md input
    = do ctx <- digestInit md
         digestUpdateBS ctx input
         return ctx


digestLazily :: Digest -> L8.ByteString -> IO DigestCtx
digestLazily md lbs
    = do ctx <- digestInit md
         mapM_ (digestUpdateBS ctx) $ L8.toChunks lbs
         return ctx

-- |@'digest'@ digests a stream of data. The string must
-- not contain any letters which aren't in the range of U+0000 -
-- U+00FF.
digest :: Digest -> String -> String
digest md input
    = digestLBS md $ L8.pack input

-- |@'digestBS'@ digests a chunk of data.
digestBS :: Digest -> B8.ByteString -> String
digestBS md input
    = unsafePerformIO $
      do ctx <- digestStrictly md input
         digestFinal ctx

digestBS' :: Digest -> B8.ByteString -> B8.ByteString
digestBS' md input
    = unsafePerformIO $
      do ctx <- digestStrictly md input
         digestFinalBS ctx

-- |@'digestLBS'@ digests a stream of data.
digestLBS :: Digest -> L8.ByteString -> String
digestLBS md input
    = unsafePerformIO $
      do ctx <- digestLazily md input
         digestFinal ctx

{- HMAC ---------------------------------------------------------------------- -}

foreign import ccall unsafe "HMAC"
        _HMAC :: Ptr EVP_MD -> Ptr CChar -> CInt -> Ptr CChar -> CInt
              -> Ptr CChar -> Ptr CUInt -> IO ()

-- | Perform a private key signing using the HMAC template with a given hash
hmacBS :: Digest  -- ^ the hash function to use in the HMAC calculation
       -> B8.ByteString  -- ^ the HMAC key
       -> B8.ByteString  -- ^ the data to be signed
       -> B8.ByteString  -- ^ resulting HMAC
hmacBS (Digest md) key input =
  unsafePerformIO $
  allocaArray (#const EVP_MAX_MD_SIZE) $ \bufPtr ->
  alloca $ \bufLenPtr ->
  unsafeUseAsCStringLen key $ \(keydata, keylen) ->
  unsafeUseAsCStringLen input $ \(inputdata, inputlen) ->
  do _HMAC md keydata (fromIntegral keylen) inputdata (fromIntegral inputlen) bufPtr bufLenPtr
     bufLen <- liftM fromIntegral $ peek bufLenPtr
     B8.packCStringLen (bufPtr, bufLen)
