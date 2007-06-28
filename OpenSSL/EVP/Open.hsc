{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Open
    ( open
    , openBS
    , openLBS
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
         withCipherCtxPtr ctx $ \ ctxPtr ->
             withCStringLen encKey $ \ (encKeyPtr, encKeyLen) ->
                 withCString iv $ \ ivPtr ->
                     withPKeyPtr pkey $ \ pkeyPtr ->
                         _OpenInit ctxPtr cipher encKeyPtr encKeyLen ivPtr pkeyPtr
                              >>= failIf (== 0)
         return ctx


open :: EvpCipher
     -> String
     -> String
     -> EvpPKey
     -> String
     -> IO String
open cipher encKey iv pkey input
    = liftM L8.unpack $ openLBS cipher encKey iv pkey $ L8.pack input


openBS :: EvpCipher
       -> String
       -> String
       -> EvpPKey
       -> ByteString
       -> IO ByteString
openBS cipher encKey iv pkey input
    = do ctx      <- openInit cipher encKey iv pkey
         cipherStrictly ctx input


openLBS :: EvpCipher
        -> String
        -> String
        -> EvpPKey
        -> LazyByteString
        -> IO LazyByteString
openLBS cipher encKey iv pkey input
    = do ctx <- openInit cipher encKey iv pkey
         cipherLazily ctx input
