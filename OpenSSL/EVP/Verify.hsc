{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Verify
    ( verify
    , verifyBS
    , verifyLBS
    )
    where

import           Control.Monad
import           Data.ByteString as B
import           Data.ByteString.Base
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Data.Typeable
import           Foreign
import           Foreign.C
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils

data VerifyStatus = VerifySuccess
                  | VerifyFailure
                    deriving (Show, Eq, Typeable)


foreign import ccall unsafe "EVP_VerifyFinal"
        _VerifyFinal :: Ptr EVP_MD_CTX -> Ptr CChar -> CUInt -> Ptr EVP_PKEY -> IO Int


verifyFinalBS :: EvpMDCtx -> String -> EvpPKey -> IO VerifyStatus
verifyFinalBS ctx sig pkey
    = withDigestCtxPtr ctx $ \ ctxPtr ->
      withCStringLen sig $ \ (buf, len) ->
      withPKeyPtr pkey $ \ pkeyPtr ->
      _VerifyFinal ctxPtr buf (fromIntegral len) pkeyPtr >>= interpret
    where
      interpret :: Int -> IO VerifyStatus
      interpret 1 = return VerifySuccess
      interpret 0 = return VerifyFailure
      interpret _ = raiseOpenSSLError


verify :: EvpMD -> String -> EvpPKey -> String -> IO VerifyStatus
verify md sig pkey input
    = verifyLBS md sig pkey (L8.pack input)


verifyBS :: EvpMD -> String -> EvpPKey -> ByteString -> IO VerifyStatus
verifyBS md sig pkey input
    = do ctx <- digestStrictly md input
         verifyFinalBS ctx sig pkey


verifyLBS :: EvpMD -> String -> EvpPKey -> LazyByteString -> IO VerifyStatus
verifyLBS md sig pkey input
    = do ctx <- digestLazily md input
         verifyFinalBS ctx sig pkey