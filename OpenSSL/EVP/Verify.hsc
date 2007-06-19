{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Verify
    ( verifyInit
    , verifyUpdate
    , verifyUpdateBS
    , verifyUpdateLBS
    , verifyFinal
    , verifyFinalBS
    , verifyFinalLBS
    )
    where

import           Control.Monad
import           Data.ByteString as B
import           Data.ByteString.Base
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign
import           Foreign.C
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils

data VerifyStatus = VerifySuccess
                  | VerifyFailure
                    deriving (Show, Eq)


foreign import ccall unsafe "EVP_VerifyFinal"
        _VerifyFinal :: Ptr EVP_MD_CTX -> Ptr CChar -> CUInt -> Ptr EVP_PKEY -> IO Int


verifyInit :: EvpMD -> IO EvpMDCtx
verifyInit = digestInit


verifyUpdate :: EvpMDCtx -> String -> IO ()
verifyUpdate = digestUpdate


verifyUpdateBS :: EvpMDCtx -> ByteString -> IO ()
verifyUpdateBS = digestUpdateBS


verifyUpdateLBS :: EvpMDCtx -> LazyByteString -> IO ()
verifyUpdateLBS = digestUpdateLBS


verifyFinal :: EvpMDCtx -> String -> EvpPKey -> IO VerifyStatus
verifyFinal ctx str pkey
    = verifyFinalBS ctx (B8.pack str) pkey


verifyFinalBS :: EvpMDCtx -> ByteString -> EvpPKey -> IO VerifyStatus
verifyFinalBS ctx bs pkey
    = withForeignPtr ctx $ \ ctxPtr ->
      unsafeUseAsCStringLen bs $ \ (buf, len) ->
      withForeignPtr pkey $ \ pkeyPtr ->
      _VerifyFinal ctxPtr buf (fromIntegral len) pkeyPtr >>= interpret
    where
      interpret :: Int -> IO VerifyStatus
      interpret 1 = return VerifySuccess
      interpret 0 = return VerifyFailure
      interpret _ = raiseOpenSSLError


verifyFinalLBS :: EvpMDCtx -> LazyByteString -> EvpPKey -> IO VerifyStatus
verifyFinalLBS ctx (LPS chunks) pkey
    = (return . B.concat) chunks >>= \ bs -> verifyFinalBS ctx bs pkey
