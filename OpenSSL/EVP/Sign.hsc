{- -*- haskell -*- -}

-- |Message signing using asymmetric cipher and message digest
-- algorithm. This is an opposite of "OpenSSL.EVP.Verify".

module OpenSSL.EVP.Sign
    ( sign
    , signBS
    , signLBS
    )
    where

import           Control.Monad
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign
import           Foreign.C
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils


foreign import ccall unsafe "EVP_SignFinal"
        _SignFinal :: Ptr EVP_MD_CTX -> Ptr CChar -> Ptr CUInt -> Ptr EVP_PKEY -> IO Int


signFinal :: DigestCtx -> PKey -> IO String
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


-- |@'sign'@ generates a signature from a stream of data. The string
-- must not contain any letters which aren't in the range of U+0000 -
-- U+00FF.
sign :: Digest    -- ^ message digest algorithm to use
     -> PKey      -- ^ private key to sign the message digest
     -> String    -- ^ input string
     -> IO String -- ^ the result signature
sign md pkey input
    = signLBS md pkey $ L8.pack input

-- |@'signBS'@ generates a signature from a chunk of data.
signBS :: Digest     -- ^ message digest algorithm to use
       -> PKey       -- ^ private key to sign the message digest
       -> B8.ByteString -- ^ input string
       -> IO String  -- ^ the result signature
signBS md pkey input
    = do ctx <- digestStrictly md input
         signFinal ctx pkey

-- |@'signLBS'@ generates a signature from a stream of data.
signLBS :: Digest         -- ^ message digest algorithm to use
        -> PKey           -- ^ private key to sign the message digest
        -> L8.ByteString -- ^ input string
        -> IO String      -- ^ the result signature
signLBS md pkey input
    = do ctx <- digestLazily md input
         signFinal ctx pkey
