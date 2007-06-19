{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Cipher
    ( EvpCipher
    , EVP_CIPHER
    , getCipherByName
    , cipherIvLength

    , EvpCipherCtx
    , EVP_CIPHER_CTX
    , newCtx -- private

    , CryptoMode(..)

    , cipherStrictly -- private
    , cipherLazily -- private

    , cipher
    , cipherBS
    , cipherLBS
    )
    where

import           Control.Monad
import qualified Data.ByteString as B
import           Data.ByteString.Base
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign
import           Foreign.C
import           OpenSSL.RSA
import           OpenSSL.Utils
import           System.IO.Unsafe


{- EVP_CIPHER ---------------------------------------------------------------- -}

type EvpCipher  = Ptr EVP_CIPHER
data EVP_CIPHER = EVP_CIPHER


foreign import ccall unsafe "EVP_get_cipherbyname"
        _get_cipherbyname :: CString -> IO EvpCipher


foreign import ccall unsafe "HsOpenSSL_EVP_CIPHER_iv_length"
        cipherIvLength :: EvpCipher -> Int


getCipherByName :: String -> IO (Maybe EvpCipher)
getCipherByName name
    = withCString name $ \ namePtr ->
      do ptr <- _get_cipherbyname namePtr
         if ptr == nullPtr then
             return Nothing
           else
             return $ Just ptr


{- EVP_CIPHER_CTX ------------------------------------------------------------ -}

type EvpCipherCtx   = ForeignPtr EVP_CIPHER_CTX
data EVP_CIPHER_CTX = EVP_CIPHER_CTX


foreign import ccall unsafe "EVP_CIPHER_CTX_init"
        _ctx_init :: Ptr EVP_CIPHER_CTX -> IO ()

foreign import ccall unsafe "&EVP_CIPHER_CTX_cleanup"
        _ctx_cleanup :: FunPtr (Ptr EVP_CIPHER_CTX -> IO ())

foreign import ccall unsafe "HsOpenSSL_EVP_CIPHER_CTX_block_size"
        _ctx_block_size :: Ptr EVP_CIPHER_CTX -> Int


newCtx :: IO EvpCipherCtx
newCtx = do ctx <- mallocForeignPtrBytes (#size EVP_CIPHER_CTX)
            withForeignPtr ctx $ \ ctxPtr ->
                _ctx_init ctxPtr
            addForeignPtrFinalizer _ctx_cleanup ctx
            return ctx


{- encrypt/decrypt ----------------------------------------------------------- -}

data CryptoMode = Encrypt
                | Decrypt


foreign import ccall unsafe "EVP_CipherInit"
        _CipherInit :: Ptr EVP_CIPHER_CTX -> EvpCipher -> CString -> CString -> Int -> IO Int

foreign import ccall unsafe "EVP_CipherUpdate"
        _CipherUpdate :: Ptr EVP_CIPHER_CTX -> Ptr CChar -> Ptr Int -> Ptr CChar -> Int -> IO Int

foreign import ccall unsafe "EVP_CipherFinal"
        _CipherFinal :: Ptr EVP_CIPHER_CTX -> Ptr CChar -> Ptr Int -> IO Int


cryptoModeToInt :: CryptoMode -> Int
cryptoModeToInt Encrypt = 1
cryptoModeToInt Decrypt = 0


cipherInit :: EvpCipher -> String -> String -> CryptoMode -> IO EvpCipherCtx
cipherInit c key iv mode
    = do ctx <- newCtx
         withForeignPtr ctx $ \ ctxPtr ->
             withCString key $ \ keyPtr ->
                 withCString iv $ \ ivPtr ->
                     _CipherInit ctxPtr c keyPtr ivPtr (cryptoModeToInt mode)
                          >>= failIf (/= 1)
         return ctx


cipherUpdateBS :: EvpCipherCtx -> ByteString -> IO ByteString
cipherUpdateBS ctx inBS
    = withForeignPtr ctx $ \ ctxPtr ->
      unsafeUseAsCStringLen inBS $ \ (inBuf, inLen) ->
      createAndTrim (inLen + _ctx_block_size ctxPtr - 1) $ \ outBuf ->
      alloca $ \ outLenPtr ->
      _CipherUpdate ctxPtr (unsafeCoercePtr outBuf) outLenPtr inBuf inLen
           >>= failIf (/= 1)
           >>  peek outLenPtr


cipherFinalBS :: EvpCipherCtx -> IO ByteString
cipherFinalBS ctx
    = withForeignPtr ctx $ \ ctxPtr ->
      createAndTrim (_ctx_block_size ctxPtr) $ \ outBuf ->
      alloca $ \ outLenPtr ->
      _CipherFinal ctxPtr (unsafeCoercePtr outBuf) outLenPtr
           >>= failIf (/= 1)
           >>  peek outLenPtr


cipher :: EvpCipher
       -> String
       -> String
       -> CryptoMode
       -> String
       -> IO String
cipher c key iv mode input
    = liftM L8.unpack $ cipherLBS c key iv mode $ L8.pack input


cipherBS :: EvpCipher
         -> String
         -> String
         -> CryptoMode
         -> ByteString
         -> IO ByteString
cipherBS c key iv mode input
    = do ctx <- cipherInit c key iv mode
         cipherStrictly ctx input


cipherLBS :: EvpCipher
          -> String
          -> String
          -> CryptoMode
          -> LazyByteString
          -> IO LazyByteString
cipherLBS c key iv mode input
    = do ctx <- cipherInit c key iv mode
         cipherLazily ctx input


cipherStrictly :: EvpCipherCtx -> ByteString -> IO ByteString
cipherStrictly ctx input
    = do output'  <- cipherUpdateBS ctx input
         output'' <- cipherFinalBS ctx
         return $ B.append output' output''


cipherLazily :: EvpCipherCtx -> LazyByteString -> IO LazyByteString

cipherLazily ctx (LPS [])
    = cipherFinalBS ctx >>= \ bs -> (return . LPS) [bs]

cipherLazily ctx (LPS (x:xs))
    = do y      <- cipherUpdateBS ctx x
         LPS ys <- unsafeInterleaveIO $
                   cipherLazily ctx (LPS xs)
         return $ LPS (y:ys)
