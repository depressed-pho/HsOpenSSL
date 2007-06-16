{- -*- haskell -*- -}
module OpenSSL.EVP.Sign
    ( initSign
    , updateSign
    , updateSignBS
    , updateSignLBS
    , finalizeSign
    , finalizeSignBS
    , finalizeSignLBS
    )
    where

#include "HsOpenSSL.h"

import           Control.Monad
import           Data.ByteString.Base
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign
import           Foreign.C
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils


foreign import ccall unsafe "EVP_SignFinal"
        _SignFinal :: Ptr EVP_MD_CTX -> Ptr CUChar -> Ptr CUInt -> Ptr EVP_PKEY -> IO Int


initSign :: EvpMD -> IO EvpMDCtx
initSign = initDigest

updateSign :: EvpMDCtx -> String -> IO ()
updateSign = updateDigest

updateSignBS :: EvpMDCtx -> ByteString -> IO ()
updateSignBS = updateDigestBS

updateSignLBS :: EvpMDCtx -> LazyByteString -> IO ()
updateSignLBS = updateDigestLBS


finalizeSign :: EvpMDCtx -> EvpPKey -> IO String
finalizeSign ctx pkey
    = liftM B8.unpack $ finalizeSignBS ctx pkey


finalizeSignBS :: EvpMDCtx -> EvpPKey -> IO ByteString
finalizeSignBS ctx pkey
    = do maxLen <- pkeySize pkey
         withForeignPtr ctx  $ \ ctxPtr  ->
             withForeignPtr pkey $ \ pkeyPtr ->
                 createAndTrim maxLen $ \ buf ->
                     alloca $ \ bufLen ->
                         do _SignFinal ctxPtr (unsafeCoercePtr buf) bufLen pkeyPtr >>= failIf (/= 1)
                            liftM fromIntegral $ peek bufLen


finalizeSignLBS :: EvpMDCtx -> EvpPKey -> IO LazyByteString
finalizeSignLBS ctx pkey
    = finalizeSignBS ctx pkey >>= \ bs -> (return . LPS) [bs]
