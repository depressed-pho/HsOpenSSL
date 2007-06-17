{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Seal
    ( sealInit
    , sealUpdate
    , sealUpdateBS
    , sealUpdateLBS
    , sealFinal
    , sealFinalBS
    , sealFinalLBS
    )
    where

import           Control.Monad
import           Data.ByteString.Base
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign
import           Foreign.C
import           OpenSSL.EVP.Cipher
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils

foreign import ccall unsafe "EVP_SealInit"
        _SealInit :: Ptr EVP_CIPHER_CTX
                  -> EvpCipher
                  -> Ptr (Ptr CChar)
                  -> Ptr Int
                  -> CString
                  -> Ptr (Ptr EVP_PKEY)
                  -> Int
                  -> IO Int


sealInit :: EvpCipher -> [EvpPKey] -> IO (EvpCipherCtx, [String], String)

sealInit _ []
    = fail "sealInit: at least one public key is required"

sealInit cipher pubKeys
    = do ctx <- newCtx
         
         -- 暗号化された共通鍵の配列が書き込まれる場所を作る。各共通鍵
         -- は最大で pkeySize の長さになる。
         encKeyBufs <- mapM mallocEncKeyBuf pubKeys

         -- encKeys は [Ptr a] なので、これを Ptr (Ptr CUChar) に
         -- しなければならない。
         encKeyBufsPtr <- newArray encKeyBufs

         -- 暗号化された共通鍵の各々の長さが書き込まれる場所を作る。
         encKeyBufsLenPtr <- mallocArray nKeys

         -- IV の書き込まれる場所を作る。
         ivPtr <- mallocArray (cipherIvLength cipher)

         -- [EvpPKey] から Ptr (Ptr EVP_PKEY) を作る。後でそれぞれの
         -- EvpPKey を touchForeignPtr する事を忘れてはならない。
         pubKeysPtr <- newArray $ map unsafeForeignPtrToPtr pubKeys

         -- 確保した領域を解放する IO アクションを作って置く
         let cleanup = do mapM_ free encKeyBufs
                          free encKeyBufsPtr
                          free encKeyBufsLenPtr
                          free ivPtr
                          free pubKeysPtr
                          mapM_ touchForeignPtr pubKeys

         -- いよいよ EVP_SealInit を呼ぶ。
         ret <- withForeignPtr ctx $ \ ctxPtr ->
                _SealInit ctxPtr cipher encKeyBufsPtr encKeyBufsLenPtr ivPtr pubKeysPtr nKeys

         if ret == 0 then
             cleanup >> raiseOpenSSLError
           else
             do encKeysLen <- peekArray nKeys encKeyBufsLenPtr
                encKeys    <- mapM peekCStringLen $ zip encKeyBufs encKeysLen
                iv         <- peekCString ivPtr
                cleanup
                return (ctx, encKeys, iv)
    where
      nKeys :: Int
      nKeys = length pubKeys

      mallocEncKeyBuf :: Storable a => EvpPKey -> IO (Ptr a)
      mallocEncKeyBuf pubKey
          = pkeySize pubKey >>= mallocArray


sealUpdate :: EvpCipherCtx -> String -> IO String
sealUpdate = cipherUpdate

sealUpdateBS :: EvpCipherCtx -> ByteString -> IO ByteString
sealUpdateBS = cipherUpdateBS

sealUpdateLBS :: EvpCipherCtx -> LazyByteString -> IO LazyByteString
sealUpdateLBS = cipherUpdateLBS

sealFinal :: EvpCipherCtx -> IO String
sealFinal = cipherFinal

sealFinalBS :: EvpCipherCtx -> IO ByteString
sealFinalBS = cipherFinalBS

sealFinalLBS :: EvpCipherCtx -> IO LazyByteString
sealFinalLBS = cipherFinalLBS