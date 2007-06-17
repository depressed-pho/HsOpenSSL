{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Open
    ( openInit
    , openUpdate
    , openUpdateBS
    , openUpdateLBS
    , openFinal
    , openFinalBS
    , openFinalLBS
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

foreign import ccall unsafe "EVP_OpenInit"
        _OpenInit :: Ptr EVP_CIPHER_CTX
                  -> EvpCipher
                  -> Ptr CChar
                  -> Int
                  -> CString
                  -> Ptr EVP_PKEY
                  -> IO Int


openInit :: EvpCipher -> String -> String -> EvpPKey -> IO EvpCipherCtx
openInit cipher encKey iv pkey
    = do ctx <- newCtx
         withForeignPtr ctx $ \ ctxPtr ->
             withCStringLen encKey $ \ (encKeyPtr, encKeyLen) ->
                 withCString iv $ \ ivPtr ->
                     withForeignPtr pkey $ \ pkeyPtr ->
                         _OpenInit ctxPtr cipher encKeyPtr encKeyLen ivPtr pkeyPtr
                              >>= failIf (== 0)
         return ctx


openUpdate :: EvpCipherCtx -> String -> IO String
openUpdate = cipherUpdate

openUpdateBS :: EvpCipherCtx -> ByteString -> IO ByteString
openUpdateBS = cipherUpdateBS

openUpdateLBS :: EvpCipherCtx -> LazyByteString -> IO LazyByteString
openUpdateLBS = cipherUpdateLBS

openFinal :: EvpCipherCtx -> IO String
openFinal = cipherFinal

openFinalBS :: EvpCipherCtx -> IO ByteString
openFinalBS = cipherFinalBS

openFinalLBS :: EvpCipherCtx -> IO LazyByteString
openFinalLBS = cipherFinalLBS