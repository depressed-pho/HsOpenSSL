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
    , cryptoModeToInt -- private

    , cipherInit
    , cipherUpdate
    , cipherUpdateBS
    , cipherUpdateLBS
    , cipherFinal
    , cipherFinalBS
    , cipherFinalLBS
    )
    where

import           Data.ByteString.Base
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign
import           Foreign.C
import           OpenSSL.RSA
import           OpenSSL.Utils


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
cipherInit cipher key iv mode
    = do ctx <- newCtx
         withForeignPtr ctx $ \ ctxPtr ->
             withCString key $ \ keyPtr ->
                 withCString iv $ \ ivPtr ->
                     _CipherInit ctxPtr cipher keyPtr ivPtr (cryptoModeToInt mode)
                          >>= failIf (/= 1)
         return ctx


cipherUpdate :: EvpCipherCtx -> String -> IO String
cipherUpdate ctx inStr
    = cipherUpdateLBS ctx (L8.pack inStr) >>= return . L8.unpack


cipherUpdateBS :: EvpCipherCtx -> ByteString -> IO ByteString
cipherUpdateBS ctx inBS
    = withForeignPtr ctx $ \ ctxPtr ->
      unsafeUseAsCStringLen inBS $ \ (inBuf, inLen) ->
      createAndTrim (inLen + _ctx_block_size ctxPtr - 1) $ \ outBuf ->
      alloca $ \ outLenPtr ->
      _CipherUpdate ctxPtr (unsafeCoercePtr outBuf) outLenPtr inBuf inLen
           >>= failIf (/= 1)
           >>  peek outLenPtr


cipherUpdateLBS :: EvpCipherCtx -> LazyByteString -> IO LazyByteString
cipherUpdateLBS ctx (LPS inChunks)
    = mapM (cipherUpdateBS ctx) inChunks >>= return . LPS


cipherFinal :: EvpCipherCtx -> IO String
cipherFinal ctx
    = cipherFinalBS ctx >>= return . B8.unpack


cipherFinalBS :: EvpCipherCtx -> IO ByteString
cipherFinalBS ctx
    = withForeignPtr ctx $ \ ctxPtr ->
      createAndTrim (_ctx_block_size ctxPtr) $ \ outBuf ->
      alloca $ \ outLenPtr ->
      _CipherFinal ctxPtr (unsafeCoercePtr outBuf) outLenPtr
           >>= failIf (/= 1)
           >>  peek outLenPtr


cipherFinalLBS :: EvpCipherCtx -> IO LazyByteString
cipherFinalLBS ctx
    = cipherFinalBS ctx >>= \ bs -> (return . LPS) [bs]
