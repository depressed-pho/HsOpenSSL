{- -*- haskell -*- -}

-- |Asymmetric cipher decryption using encrypted symmetric key. This
-- is an opposite of "OpenSSL.EVP.Open".

module OpenSSL.EVP.Seal
    ( seal
    , sealBS
    , sealLBS
    )
    where

import           Control.Monad
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign
import           Foreign.C
import           OpenSSL.EVP.Cipher hiding (cipher)
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils


foreign import ccall unsafe "EVP_SealInit"
        _SealInit :: Ptr EVP_CIPHER_CTX
                  -> Cipher
                  -> Ptr (Ptr CChar)
                  -> Ptr CInt
                  -> CString
                  -> Ptr (Ptr EVP_PKEY)
                  -> CInt
                  -> IO CInt


sealInit :: Cipher -> [PKey] -> IO (CipherCtx, [String], String)

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

         -- [PKey] から Ptr (Ptr EVP_PKEY) を作る。後でそれぞれの
         -- PKey を touchForeignPtr する事を忘れてはならない。
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
                _SealInit ctxPtr cipher encKeyBufsPtr encKeyBufsLenPtr ivPtr pubKeysPtr (fromIntegral nKeys)

         if ret == 0 then
             cleanup >> raiseOpenSSLError
           else
             do encKeysLen <- peekArray nKeys encKeyBufsLenPtr
                encKeys    <- mapM peekCStringCLen $ zip encKeyBufs encKeysLen
                iv         <- peekCString ivPtr
                cleanup
                return (ctx, encKeys, iv)
    where
      nKeys :: Int
      nKeys = length pubKeys

      mallocEncKeyBuf :: Storable a => PKey -> IO (Ptr a)
      mallocEncKeyBuf pubKey
          = pkeySize pubKey >>= mallocArray

-- |@'seal'@ lazilly encrypts a stream of data. The input string
-- doesn't necessarily have to be finite.
seal :: Cipher        -- ^ symmetric cipher algorithm to use
     -> [PKey]        -- ^ A list of public keys to encrypt a
                      --   symmetric key. At least one public key must
                      --   be supplied. If two or more keys are given,
                      --   the symmetric key are encrypted by each
                      --   public keys so that any of the
                      --   corresponding private keys can decrypt the
                      --   message.
     -> String        -- ^ input string to encrypt
     -> IO (String, [String], String) -- ^ (encrypted string, list of
                                      --   encrypted asymmetric keys,
                                      --   IV)
seal cipher pubKeys input
    = do (output, encKeys, iv) <- sealLBS cipher pubKeys $ L8.pack input
         return (L8.unpack output, encKeys, iv)

-- |@'sealBS'@ strictly encrypts a chunk of data.
sealBS :: Cipher     -- ^ symmetric cipher algorithm to use
       -> [PKey]     -- ^ list of public keys to encrypt a symmetric
                     --   key
       -> B8.ByteString -- ^ input string to encrypt
       -> IO (B8.ByteString, [String], String) -- ^ (encrypted string,
                                            --   list of encrypted
                                            --   asymmetric keys, IV)
sealBS cipher pubKeys input
    = do (ctx, encKeys, iv) <- sealInit cipher pubKeys
         output             <- cipherStrictly ctx input
         return (output, encKeys, iv)

-- |@'sealLBS'@ lazilly encrypts a stream of data. The input string
-- doesn't necessarily have to be finite.
sealLBS :: Cipher         -- ^ symmetric cipher algorithm to use
        -> [PKey]         -- ^ list of public keys to encrypt a
                          --   symmetric key
        -> L8.ByteString -- ^ input string to encrypt
        -> IO (L8.ByteString, [String], String) -- ^ (encrypted
                                                 --   string, list of
                                                 --   encrypted
                                                 --   asymmetric keys,
                                                 --   IV)
sealLBS cipher pubKeys input
    = do (ctx, encKeys, iv) <- sealInit cipher pubKeys
         output             <- cipherLazily ctx input
         return (output, encKeys, iv)
