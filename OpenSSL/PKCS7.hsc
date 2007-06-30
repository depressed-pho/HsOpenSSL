{- -*- haskell -*- -}

#include "HsOpenSSL.h"

module OpenSSL.PKCS7
    ( Pkcs7
    , PKCS7
    , Pkcs7Flag(..)
    , wrapPkcs7Ptr -- private
    , withPkcs7Ptr -- private

    , isDetachedSignature

    , pkcs7Sign
    , pkcs7Verify
    , pkcs7Encrypt
    , pkcs7Decrypt

    , writeSmime
    , readSmime
    )
    where

import           Data.Bits
import qualified Data.ByteString            as B
import           Data.ByteString.Base
import qualified Data.ByteString.Char8      as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Data.List
import           Data.Traversable
import           Data.Typeable
import           Foreign
import           Foreign.C
import           OpenSSL.BIO
import           OpenSSL.EVP.Cipher
import           OpenSSL.EVP.PKey
import           OpenSSL.Stack
import           OpenSSL.Utils
import           OpenSSL.X509
import           OpenSSL.X509.Store


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
                 deriving (Show, Eq, Typeable)

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


data VerifyStatus = VerifySuccess (Maybe String)
                  | VerifyFailure
                    deriving (Show, Eq, Typeable)


flagListToInt :: [Pkcs7Flag] -> Int
flagListToInt = foldl' (.|.) 0 . map flagToInt


foreign import ccall "&PKCS7_free"
        _free :: FunPtr (Ptr PKCS7 -> IO ())

foreign import ccall "HsOpenSSL_PKCS7_is_detached"
        _is_detached :: Ptr PKCS7 -> IO CLong

foreign import ccall "PKCS7_sign"
        _sign :: Ptr X509_ -> Ptr EVP_PKEY -> Ptr STACK -> Ptr BIO_ -> Int -> IO (Ptr PKCS7)

foreign import ccall "PKCS7_verify"
        _verify :: Ptr PKCS7 -> Ptr STACK -> Ptr X509_STORE -> Ptr BIO_ -> Ptr BIO_ -> Int -> IO Int

foreign import ccall "PKCS7_encrypt"
        _encrypt :: Ptr STACK -> Ptr BIO_ -> Ptr EVP_CIPHER -> Int -> IO (Ptr PKCS7)

foreign import ccall "PKCS7_decrypt"
        _decrypt :: Ptr PKCS7 -> Ptr EVP_PKEY -> Ptr X509_ -> Ptr BIO_ -> Int -> IO Int


wrapPkcs7Ptr :: Ptr PKCS7 -> IO Pkcs7
wrapPkcs7Ptr p7Ptr = newForeignPtr _free p7Ptr >>= return . Pkcs7


withPkcs7Ptr :: Pkcs7 -> (Ptr PKCS7 -> IO a) -> IO a
withPkcs7Ptr (Pkcs7 pkcs7) = withForeignPtr pkcs7


isDetachedSignature :: Pkcs7 -> IO Bool
isDetachedSignature pkcs7
    = withPkcs7Ptr pkcs7 $ \ pkcs7Ptr ->
      _is_detached pkcs7Ptr
           >>= return . (== 1)


pkcs7Sign' :: X509 -> EvpPKey -> [X509] -> BIO -> [Pkcs7Flag] -> IO Pkcs7
pkcs7Sign' signCert pkey certs input flagList
    = withX509Ptr signCert $ \ signCertPtr ->
      withPKeyPtr pkey     $ \ pkeyPtr     ->
      withX509Stack certs  $ \ certStack   ->
      withBioPtr input     $ \ inputPtr    ->
      _sign signCertPtr pkeyPtr certStack inputPtr (flagListToInt flagList)
           >>= failIfNull
           >>= wrapPkcs7Ptr


pkcs7Sign :: X509 -> EvpPKey -> [X509] -> String -> [Pkcs7Flag] -> IO Pkcs7
pkcs7Sign signCert pkey certs input flagList
    = do mem <- newConstMem input
         pkcs7Sign' signCert pkey certs mem flagList


pkcs7Verify' :: Pkcs7 -> [X509] -> X509Store -> Maybe BIO -> [Pkcs7Flag] -> IO (Maybe BIO, Bool)
pkcs7Verify' pkcs7 certs store inData flagList
    = withPkcs7Ptr pkcs7     $ \ pkcs7Ptr  ->
      withX509Stack certs    $ \ certStack ->
      withX509StorePtr store $ \ storePtr  ->
      withBioPtr' inData     $ \ inDataPtr ->
      do isDetached <- isDetachedSignature pkcs7
         outData    <- if isDetached then
                           return Nothing
                       else
                           newMem >>= return . Just
         withBioPtr' outData $ \ outDataPtr ->
             _verify pkcs7Ptr certStack storePtr inDataPtr outDataPtr (flagListToInt flagList)
                  >>= interpret outData
    where
      interpret :: Maybe BIO -> Int -> IO (Maybe BIO, Bool)
      interpret bio 1 = return (bio    , True )
      interpret _   _ = return (Nothing, False)


pkcs7Verify :: Pkcs7 -> [X509] -> X509Store -> Maybe String -> [Pkcs7Flag] -> IO VerifyStatus
pkcs7Verify pkcs7 certs store inData flagList
    = do inDataBio               <- forM inData newConstMem
         (outDataBio, isSuccess) <- pkcs7Verify' pkcs7 certs store inDataBio flagList
         if isSuccess then
             do outData <- forM outDataBio bioRead
                return $ VerifySuccess outData
           else
             return VerifyFailure


pkcs7Encrypt' :: [X509] -> BIO -> EvpCipher -> [Pkcs7Flag] -> IO Pkcs7
pkcs7Encrypt' certs input cipher flagList
    = withX509Stack certs  $ \ certsPtr  ->
      withBioPtr    input  $ \ inputPtr  ->
      withCipherPtr cipher $ \ cipherPtr ->
      _encrypt certsPtr inputPtr cipherPtr (flagListToInt flagList)
           >>= failIfNull
           >>= wrapPkcs7Ptr


pkcs7Encrypt :: [X509] -> String -> EvpCipher -> [Pkcs7Flag] -> IO Pkcs7
pkcs7Encrypt certs input cipher flagList
    = do mem <- newConstMem input
         pkcs7Encrypt' certs mem cipher flagList


pkcs7Decrypt' :: Pkcs7 -> EvpPKey -> X509 -> BIO -> [Pkcs7Flag] -> IO ()
pkcs7Decrypt' pkcs7 pkey cert output flagList
    = withPkcs7Ptr pkcs7  $ \ pkcs7Ptr  ->
      withPKeyPtr  pkey   $ \ pkeyPtr   ->
      withX509Ptr  cert   $ \ certPtr   ->
      withBioPtr   output $ \ outputPtr ->
      _decrypt pkcs7Ptr pkeyPtr certPtr outputPtr (flagListToInt flagList)
           >>= failIf (/= 1)
           >>  return ()


pkcs7Decrypt :: Pkcs7 -> EvpPKey -> X509 -> [Pkcs7Flag] -> IO String
pkcs7Decrypt pkcs7 pkey cert flagList
    = do mem <- newMem
         pkcs7Decrypt' pkcs7 pkey cert mem flagList
         bioRead mem


{- S/MIME -------------------------------------------------------------------- -}

foreign import ccall unsafe "SMIME_write_PKCS7"
        _SMIME_write_PKCS7 :: Ptr BIO_ -> Ptr PKCS7 -> Ptr BIO_ -> Int -> IO Int

foreign import ccall unsafe "SMIME_read_PKCS7"
        _SMIME_read_PKCS7 :: Ptr BIO_ -> Ptr (Ptr BIO_) -> IO (Ptr PKCS7)


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


readSmime :: String -> IO (Pkcs7, Maybe String)
readSmime input
    = do inBio           <- newConstMem input
         (pkcs7, outBio) <- readSmime' inBio
         output          <- forM outBio bioRead
         return (pkcs7, output)


readSmime' :: BIO -> IO (Pkcs7, Maybe BIO)
readSmime' inBio
    = withBioPtr inBio $ \ inBioPtr     ->
      alloca           $ \ outBioPtrPtr ->
      do poke outBioPtrPtr nullPtr

         pkcs7     <- _SMIME_read_PKCS7 inBioPtr outBioPtrPtr
                      >>= failIfNull
                      >>= wrapPkcs7Ptr
         outBioPtr <- peek outBioPtrPtr
         outBio    <- if outBioPtr == nullPtr then
                          return Nothing
                      else
                          wrapBioPtr outBioPtr >>= return . Just

         return (pkcs7, outBio)
