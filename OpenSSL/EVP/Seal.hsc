{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Seal
    ( seal
    , sealBS
    , sealLBS
    )
    where

import           Control.Monad
import qualified Data.ByteString as B
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

         -- encKeys は [Ptr a] なので、これを Ptr (Ptr CChar) にしなけ
         -- ればならない。
         encKeyBufsPtr <- newArray encKeyBufs

         -- 暗号化された共通鍵の各々の長さが書き込まれる場所を作る。
         encKeyBufsLenPtr <- mallocArray nKeys

         -- IV の書き込まれる場所を作る。
         ivPtr <- mallocArray (cipherIvLength cipher)

         -- [EvpPKey] から Ptr (Ptr EVP_PKEY) を作る。後でそれぞれの
         -- EvpPKey を touchForeignPtr する事を忘れてはならない。
         pubKeysPtr <- newArray $ map unsafePKeyToPtr pubKeys

         -- 確保した領域を解放する IO アクションを作って置く
         let cleanup = do mapM_ free encKeyBufs
                          free encKeyBufsPtr
                          free encKeyBufsLenPtr
                          free ivPtr
                          free pubKeysPtr
                          mapM_ touchPKey pubKeys

         -- いよいよ EVP_SealInit を呼ぶ。
         ret <- withCipherCtxPtr ctx $ \ ctxPtr ->
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


seal :: EvpCipher
     -> [EvpPKey]
     -> String
     -> IO ( String
           , [String]
           , String
           )
seal cipher pubKeys input
    = do (output, encKeys, iv) <- sealLBS cipher pubKeys $ L8.pack input
         return (L8.unpack output, encKeys, iv)


sealBS :: EvpCipher
       -> [EvpPKey]
       -> ByteString
       -> IO ( ByteString
             , [String]
             , String
             )
sealBS cipher pubKeys input
    = do (ctx, encKeys, iv) <- sealInit cipher pubKeys
         output             <- cipherStrictly ctx input
         return (output, encKeys, iv)


sealLBS :: EvpCipher
        -> [EvpPKey]
        -> LazyByteString
        -> IO ( LazyByteString
              , [String]
              , String
              )
sealLBS cipher pubKeys input
    = do (ctx, encKeys, iv) <- sealInit cipher pubKeys
         output             <- cipherLazily ctx input
         return (output, encKeys, iv)
