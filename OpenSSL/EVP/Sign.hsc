{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Sign
    ( sign
    , signBS
    , signLBS
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
        _SignFinal :: Ptr EVP_MD_CTX -> Ptr CChar -> Ptr CUInt -> Ptr EVP_PKEY -> IO Int


signFinal :: EvpMDCtx -> EvpPKey -> IO String
signFinal ctx pkey
    = do maxLen <- pkeySize pkey
         withDigestCtxPtr ctx $ \ ctxPtr ->
             withPKeyPtr pkey $ \ pkeyPtr ->
                 allocaArray maxLen $ \ bufPtr ->
                     alloca $ \ bufLenPtr ->
                         do _SignFinal ctxPtr bufPtr bufLenPtr pkeyPtr
                                 >>= failIf (/= 1)
                            bufLen <- liftM fromIntegral $ peek bufLenPtr
                            peekCStringLen (bufPtr, bufLen)


sign :: EvpMD -> EvpPKey -> String -> IO String
sign md pkey input
    = signLBS md pkey $ L8.pack input


signBS :: EvpMD -> EvpPKey -> ByteString -> IO String
signBS md pkey input
    = do ctx <- digestStrictly md input
         signFinal ctx pkey


signLBS :: EvpMD -> EvpPKey -> LazyByteString -> IO String
signLBS md pkey input
    = do ctx <- digestLazily md input
         signFinal ctx pkey
