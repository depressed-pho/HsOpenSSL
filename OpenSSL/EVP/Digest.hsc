{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Digest
    ( EvpMD
    , EVP_MD
    , getDigestByName
    , getDigestNames

    , EvpMDCtx
    , EVP_MD_CTX

    , digestStrictly -- private
    , digestLazily   -- private

    , digest
    , digestBS
    , digestLBS
    )
    where

import           Control.Monad
import           Data.ByteString.Base
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign
import           Foreign.C
import           OpenSSL.Objects
import           OpenSSL.Utils


{- EVP_MD -------------------------------------------------------------------- -}

type EvpMD  = Ptr EVP_MD
data EVP_MD = EVP_MD


foreign import ccall unsafe "EVP_get_digestbyname"
        _get_digestbyname :: CString -> IO EvpMD

foreign import ccall unsafe "HsOpenSSL_EVP_MD_size"
        mdSize :: EvpMD -> Int


getDigestByName :: String -> IO (Maybe EvpMD)
getDigestByName name
    = withCString name $ \ namePtr ->
      do ptr <- _get_digestbyname namePtr
         if ptr == nullPtr then
             return Nothing
           else
             return $ Just ptr


getDigestNames :: IO [String]
getDigestNames = getObjNames MDMethodType True


{- EVP_MD_CTX ---------------------------------------------------------------- -}

type EvpMDCtx   = ForeignPtr EVP_MD_CTX
data EVP_MD_CTX = EVP_MD_CTX


foreign import ccall unsafe "EVP_MD_CTX_init"
        _ctx_init :: Ptr EVP_MD_CTX -> IO ()

foreign import ccall unsafe "&EVP_MD_CTX_cleanup"
        _ctx_cleanup :: FunPtr (Ptr EVP_MD_CTX -> IO ())


newCtx :: IO EvpMDCtx
newCtx = do ctx <- mallocForeignPtrBytes (#size EVP_MD_CTX)
            withForeignPtr ctx $ \ ctxPtr ->
                _ctx_init ctxPtr
            addForeignPtrFinalizer _ctx_cleanup ctx
            return ctx


{- digest -------------------------------------------------------------------- -}

foreign import ccall unsafe "EVP_DigestInit"
        _DigestInit :: Ptr EVP_MD_CTX -> Ptr EVP_MD -> IO Int

foreign import ccall unsafe "EVP_DigestUpdate"
        _DigestUpdate :: Ptr EVP_MD_CTX -> Ptr CChar -> CSize -> IO Int

foreign import ccall unsafe "EVP_DigestFinal"
        _DigestFinal :: Ptr EVP_MD_CTX -> Ptr CChar -> Ptr CUInt -> IO Int



digestInit :: EvpMD -> IO EvpMDCtx
digestInit md
    = do ctx <- newCtx
         withForeignPtr ctx $ \ ctxPtr ->
             _DigestInit ctxPtr md >>= failIf (/= 1)
         return ctx   


digestUpdateBS :: EvpMDCtx -> ByteString -> IO ()
digestUpdateBS ctx bs
    = withForeignPtr ctx $ \ ctxPtr ->
      unsafeUseAsCStringLen bs $ \ (buf, len) ->
      _DigestUpdate ctxPtr buf (fromIntegral len) >>= failIf (/= 1) >> return ()


digestUpdateLBS :: EvpMDCtx -> LazyByteString -> IO ()
digestUpdateLBS ctx (LPS chunks)
    = mapM_ (digestUpdateBS ctx) chunks


digestFinal :: EvpMDCtx -> IO String
digestFinal ctx
    = withForeignPtr ctx $ \ ctxPtr ->
      allocaArray (#const EVP_MAX_MD_SIZE) $ \ bufPtr ->
      alloca $ \ bufLenPtr ->
      do _DigestFinal ctxPtr bufPtr bufLenPtr >>= failIf (/= 1)
         bufLen <- liftM fromIntegral $ peek bufLenPtr
         peekCStringLen (bufPtr, bufLen)


digestStrictly :: EvpMD -> ByteString -> IO EvpMDCtx
digestStrictly md input
    = do ctx <- digestInit md
         digestUpdateBS ctx input
         return ctx


digestLazily :: EvpMD -> LazyByteString -> IO EvpMDCtx
digestLazily md (LPS input)
    = do ctx <- digestInit md
         mapM_ (digestUpdateBS ctx) input
         return ctx


digest :: EvpMD -> String -> IO String
digest md input
    = digestLBS md $ L8.pack input


digestBS :: EvpMD -> ByteString -> IO String
digestBS md input
    = do ctx <- digestStrictly md input
         digestFinal ctx


digestLBS :: EvpMD -> LazyByteString -> IO String
digestLBS md input
    = do ctx <- digestLazily md input
         digestFinal ctx