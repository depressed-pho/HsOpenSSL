{- -*- haskell -*- -}

#include "HsOpenSSL.h"

module OpenSSL.PKCS7
    ( Pkcs7
    , PKCS7
    , Pkcs7Flag(..)
    , wrapPkcs7Ptr -- private
    , withPkcs7Ptr -- private

    , pkcs7Sign

    , writeSmime
    )
    where

import           Data.Bits
import qualified Data.ByteString            as B
import           Data.ByteString.Base
import qualified Data.ByteString.Char8      as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Data.List
import           Data.Traversable
import           Foreign
import           Foreign.C
import           OpenSSL.BIO
import           OpenSSL.EVP.PKey
import           OpenSSL.Stack
import           OpenSSL.Utils
import           OpenSSL.X509


{- PKCS#7 -------------------------------------------------------------------- -}

newtype Pkcs7 = Pkcs7 (ForeignPtr PKCS7)
data    PKCS7 = PKCS7

data Pkcs7Flag = Pkcs7Text
               | Pkcs7NoCerts
               | Pkcs7NoSigs
               | Pkcs7NoChain
               | Pkcs7NoIntern
               | Pkcs7NoVerify
               | Pkcs7Detached
               | Pkcs7Binary
               | Pkcs7NoAttr
               | Pkcs7NoSmimeCap
               | Pkcs7NoOldMimeType
               | Pkcs7CRLFEOL

flagToInt :: Pkcs7Flag -> Int
flagToInt Pkcs7Text          = #const PKCS7_TEXT
flagToInt Pkcs7NoCerts       = #const PKCS7_NOCERTS
flagToInt Pkcs7NoSigs        = #const PKCS7_NOSIGS
flagToInt Pkcs7NoChain       = #const PKCS7_NOCHAIN
flagToInt Pkcs7NoIntern      = #const PKCS7_NOINTERN
flagToInt Pkcs7NoVerify      = #const PKCS7_NOVERIFY
flagToInt Pkcs7Detached      = #const PKCS7_DETACHED
flagToInt Pkcs7Binary        = #const PKCS7_BINARY
flagToInt Pkcs7NoAttr        = #const PKCS7_NOATTR
flagToInt Pkcs7NoSmimeCap    = #const PKCS7_NOSMIMECAP
flagToInt Pkcs7NoOldMimeType = #const PKCS7_NOOLDMIMETYPE
flagToInt Pkcs7CRLFEOL       = #const PKCS7_CRLFEOL

flagListToInt :: [Pkcs7Flag] -> Int
flagListToInt = foldl' (.|.) 0 . map flagToInt


foreign import ccall "&PKCS7_free"
        _free :: FunPtr (Ptr PKCS7 -> IO ())

foreign import ccall "PKCS7_sign"
        _sign :: Ptr X509_ -> Ptr EVP_PKEY -> Ptr STACK -> Ptr BIO_ -> Int -> IO (Ptr PKCS7)


wrapPkcs7Ptr :: Ptr PKCS7 -> IO Pkcs7
wrapPkcs7Ptr p7Ptr = newForeignPtr _free p7Ptr >>= return . Pkcs7


withPkcs7Ptr :: Pkcs7 -> (Ptr PKCS7 -> IO a) -> IO a
withPkcs7Ptr (Pkcs7 pkcs7) = withForeignPtr pkcs7


pkcs7Sign' :: X509 -> EvpPKey -> [X509] -> BIO -> [Pkcs7Flag] -> IO Pkcs7
pkcs7Sign' signCert pkey certs input flagList
    = withX509Ptr signCert $ \ signCertPtr ->
      withPKeyPtr pkey     $ \ pkeyPtr     ->
      -- [X509] から [Ptr X509_] を作る。後で touchX509 する事を
      -- 忘れてはならない。
      do let certPtrs = map unsafeX509ToPtr certs
             flags    = flagListToInt flagList

         pkcs7 <- withStack  certPtrs $ \ certStack ->
                  withBioPtr input    $ \ inputPtr ->
                      _sign signCertPtr pkeyPtr certStack inputPtr flags
                      >>= failIfNull
                      >>= wrapPkcs7Ptr

         mapM_ touchX509 certs
         return pkcs7


pkcs7Sign :: X509 -> EvpPKey -> [X509] -> String -> [Pkcs7Flag] -> IO Pkcs7
pkcs7Sign signCert pkey certs input flagList
    = do mem <- newConstMem input
         pkcs7Sign' signCert pkey certs mem flagList


{- S/MIME -------------------------------------------------------------------- -}

foreign import ccall unsafe "SMIME_write_PKCS7"
        _SMIME_write_PKCS7 :: Ptr BIO_ -> Ptr PKCS7 -> Ptr BIO_ -> Int -> IO Int


writeSmime :: Pkcs7 -> Maybe String -> [Pkcs7Flag] -> IO String
writeSmime pkcs7 dataStr flagList
    = do outBio  <- newMem
         dataBio <- forM dataStr newConstMem
         writeSmime' outBio pkcs7 dataBio flagList
         bioRead outBio


writeSmime' :: BIO -> Pkcs7 -> Maybe BIO -> [Pkcs7Flag] -> IO ()
writeSmime' outBio pkcs7 dataBio flagList
    = withBioPtr   outBio  $ \ outBioPtr  ->
      withPkcs7Ptr pkcs7   $ \ pkcs7Ptr   ->
      withBioPtr'  dataBio $ \ dataBioPtr ->
      _SMIME_write_PKCS7 outBioPtr pkcs7Ptr dataBioPtr (flagListToInt flagList)
           >>= failIf (/= 1)
           >>  return ()
    where
      withBioPtr' :: Maybe BIO -> (Ptr BIO_ -> IO a) -> IO a
      withBioPtr' Nothing    f = f nullPtr
      withBioPtr' (Just bio) f = withBioPtr bio f