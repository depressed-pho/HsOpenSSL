{- -*- haskell -*- -}

-- #prune

-- |An interface to symmetric cipher algorithms.

#include "HsOpenSSL.h"

module OpenSSL.EVP.Cipher
    ( Cipher
    , EVP_CIPHER -- private
    , withCipherPtr -- private

    , getCipherByName
    , getCipherNames

    , cipherIvLength -- private

    , CipherCtx -- private
    , EVP_CIPHER_CTX -- private
    , newCtx -- private
    , withCipherCtxPtr -- private

    , CryptoMode(..)

    , cipherStrictly -- private
    , cipherLazily -- private

    , cipher
    , cipherBS
    , cipherLBS
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
import           System.IO.Unsafe


{- EVP_CIPHER ---------------------------------------------------------------- -}

-- |@Cipher@ is an opaque object that represents an algorithm of
-- symmetric cipher.
newtype Cipher     = Cipher (Ptr EVP_CIPHER)
data    EVP_CIPHER


foreign import ccall unsafe "EVP_get_cipherbyname"
        _get_cipherbyname :: CString -> IO (Ptr EVP_CIPHER)


foreign import ccall unsafe "HsOpenSSL_EVP_CIPHER_iv_length"
        _iv_length :: Ptr EVP_CIPHER -> Int


withCipherPtr :: Cipher -> (Ptr EVP_CIPHER -> IO a) -> IO a
withCipherPtr (Cipher cipher) f = f cipher

-- |@'getCipherByName' name@ returns a symmetric cipher algorithm
-- whose name is @name@. If no algorithms are found, the result is
-- @Nothing@.
getCipherByName :: String -> IO (Maybe Cipher)
getCipherByName name
    = withCString name $ \ namePtr ->
      do ptr <- _get_cipherbyname namePtr
         if ptr == nullPtr then
             return Nothing
           else
             return $ Just $ Cipher ptr

-- |@'getCipherNames'@ returns a list of name of symmetric cipher
-- algorithms.
getCipherNames :: IO [String]
getCipherNames = getObjNames CipherMethodType True


cipherIvLength :: Cipher -> Int
cipherIvLength (Cipher cipher) = _iv_length cipher


{- EVP_CIPHER_CTX ------------------------------------------------------------ -}

newtype CipherCtx      = CipherCtx (ForeignPtr EVP_CIPHER_CTX)
data    EVP_CIPHER_CTX


foreign import ccall unsafe "EVP_CIPHER_CTX_init"
        _ctx_init :: Ptr EVP_CIPHER_CTX -> IO ()

foreign import ccall unsafe "&EVP_CIPHER_CTX_cleanup"
        _ctx_cleanup :: FunPtr (Ptr EVP_CIPHER_CTX -> IO ())

foreign import ccall unsafe "HsOpenSSL_EVP_CIPHER_CTX_block_size"
        _ctx_block_size :: Ptr EVP_CIPHER_CTX -> Int


newCtx :: IO CipherCtx
newCtx = do ctx <- mallocForeignPtrBytes (#size EVP_CIPHER_CTX)
            withForeignPtr ctx $ \ ctxPtr ->
                _ctx_init ctxPtr
            addForeignPtrFinalizer _ctx_cleanup ctx
            return $ CipherCtx ctx


withCipherCtxPtr :: CipherCtx -> (Ptr EVP_CIPHER_CTX -> IO a) -> IO a
withCipherCtxPtr (CipherCtx ctx) = withForeignPtr ctx


{- encrypt/decrypt ----------------------------------------------------------- -}

-- |@CryptoMode@ represents instruction to 'cipher' and such like.
data CryptoMode = Encrypt | Decrypt


foreign import ccall unsafe "EVP_CipherInit"
        _CipherInit :: Ptr EVP_CIPHER_CTX -> Ptr EVP_CIPHER -> CString -> CString -> Int -> IO Int

foreign import ccall unsafe "EVP_CipherUpdate"
        _CipherUpdate :: Ptr EVP_CIPHER_CTX -> Ptr CChar -> Ptr Int -> Ptr CChar -> Int -> IO Int

foreign import ccall unsafe "EVP_CipherFinal"
        _CipherFinal :: Ptr EVP_CIPHER_CTX -> Ptr CChar -> Ptr Int -> IO Int


cryptoModeToInt :: CryptoMode -> Int
cryptoModeToInt Encrypt = 1
cryptoModeToInt Decrypt = 0


cipherInit :: Cipher -> String -> String -> CryptoMode -> IO CipherCtx
cipherInit (Cipher c) key iv mode
    = do ctx <- newCtx
         withCipherCtxPtr ctx $ \ ctxPtr ->
             withCString key $ \ keyPtr ->
                 withCString iv $ \ ivPtr ->
                     _CipherInit ctxPtr c keyPtr ivPtr (cryptoModeToInt mode)
                          >>= failIf (/= 1)
         return ctx


cipherUpdateBS :: CipherCtx -> ByteString -> IO ByteString
cipherUpdateBS ctx inBS
    = withCipherCtxPtr ctx $ \ ctxPtr ->
      unsafeUseAsCStringLen inBS $ \ (inBuf, inLen) ->
      createAndTrim (inLen + _ctx_block_size ctxPtr - 1) $ \ outBuf ->
      alloca $ \ outLenPtr ->
      _CipherUpdate ctxPtr (unsafeCoercePtr outBuf) outLenPtr inBuf inLen
           >>= failIf (/= 1)
           >>  peek outLenPtr


cipherFinalBS :: CipherCtx -> IO ByteString
cipherFinalBS ctx
    = withCipherCtxPtr ctx $ \ ctxPtr ->
      createAndTrim (_ctx_block_size ctxPtr) $ \ outBuf ->
      alloca $ \ outLenPtr ->
      _CipherFinal ctxPtr (unsafeCoercePtr outBuf) outLenPtr
           >>= failIf (/= 1)
           >>  peek outLenPtr

-- |@'cipher'@ lazilly encrypts or decrypts a stream of data. The
-- input string doesn't necessarily have to be finite.
cipher :: Cipher     -- ^ algorithm to use
       -> String     -- ^ symmetric key
       -> String     -- ^ IV
       -> CryptoMode -- ^ operation
       -> String     -- ^ An input string to encrypt\/decrypt. Note
                     --   that the string must not contain any letters
                     --   which aren't in the range of U+0000 -
                     --   U+00FF.
       -> IO String  -- ^ the result string
cipher c key iv mode input
    = liftM L8.unpack $ cipherLBS c key iv mode $ L8.pack input

-- |@'cipherBS'@ strictly encrypts or decrypts a chunk of data.
cipherBS :: Cipher        -- ^ algorithm to use
         -> String        -- ^ symmetric key
         -> String        -- ^ IV
         -> CryptoMode    -- ^ operation
         -> ByteString    -- ^ input string to encrypt\/decrypt
         -> IO ByteString -- ^ the result string
cipherBS c key iv mode input
    = do ctx <- cipherInit c key iv mode
         cipherStrictly ctx input

-- |@'cipherLBS'@ lazilly encrypts or decrypts a stream of data. The
-- input string doesn't necessarily have to be finite.
cipherLBS :: Cipher            -- ^ algorithm to use
          -> String            -- ^ symmetric key
          -> String            -- ^ IV
          -> CryptoMode        -- ^ operation
          -> LazyByteString    -- ^ input string to encrypt\/decrypt
          -> IO LazyByteString -- ^ the result string
cipherLBS c key iv mode input
    = do ctx <- cipherInit c key iv mode
         cipherLazily ctx input


cipherStrictly :: CipherCtx -> ByteString -> IO ByteString
cipherStrictly ctx input
    = do output'  <- cipherUpdateBS ctx input
         output'' <- cipherFinalBS ctx
         return $ B8.append output' output''


cipherLazily :: CipherCtx -> LazyByteString -> IO LazyByteString

cipherLazily ctx (LPS [])
    = cipherFinalBS ctx >>= \ bs -> (return . LPS) [bs]

cipherLazily ctx (LPS (x:xs))
    = do y      <- cipherUpdateBS ctx x
         LPS ys <- unsafeInterleaveIO $
                   cipherLazily ctx (LPS xs)
         return $ LPS (y:ys)
