{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Sign
    ( signInit
    , signUpdate
    , signUpdateBS
    , signUpdateLBS
    , signFinal
    , signFinalBS
    , signFinalLBS
    )
    where

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


signInit :: EvpMD -> IO EvpMDCtx
signInit = digestInit

signUpdate :: EvpMDCtx -> String -> IO ()
signUpdate = digestUpdate

signUpdateBS :: EvpMDCtx -> ByteString -> IO ()
signUpdateBS = digestUpdateBS

signUpdateLBS :: EvpMDCtx -> LazyByteString -> IO ()
signUpdateLBS = digestUpdateLBS


signFinal :: EvpMDCtx -> EvpPKey -> IO String
signFinal ctx pkey
    = liftM B8.unpack $ signFinalBS ctx pkey


signFinalBS :: EvpMDCtx -> EvpPKey -> IO ByteString
signFinalBS ctx pkey
    = do maxLen <- pkeySize pkey
         withForeignPtr ctx  $ \ ctxPtr  ->
             withForeignPtr pkey $ \ pkeyPtr ->
                 createAndTrim maxLen $ \ buf ->
                     alloca $ \ bufLen ->
                         do _SignFinal ctxPtr (unsafeCoercePtr buf) bufLen pkeyPtr >>= failIf (/= 1)
                            liftM fromIntegral $ peek bufLen


signFinalLBS :: EvpMDCtx -> EvpPKey -> IO LazyByteString
signFinalLBS ctx pkey
    = signFinalBS ctx pkey >>= \ bs -> (return . LPS) [bs]
