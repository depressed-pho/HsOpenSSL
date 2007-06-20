{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.X509
    ( X509
    , X509_

    , wrapX509 -- private

    , getVersion
    , getSerialNumber
    , getIssuerName
    , getSubjectName
    , getNotBefore
    , getNotAfter
    , getPublicKey
    , getEmail
    )
    where

import           Control.Monad
import           Foreign
import           Foreign.C
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils
import           OpenSSL.Objects
import           OpenSSL.Stack
import           OpenSSL.X509.Name


{- X509 ---------------------------------------------------------------------- -}

type X509  = ForeignPtr X509_
data X509_ = X509_


foreign import ccall unsafe "&X509_free"
        _free :: FunPtr (Ptr X509_ -> IO ())

foreign import ccall unsafe "HsOpenSSL_X509_get_version"
        _get_version :: Ptr X509_ -> IO CLong

foreign import ccall unsafe "X509_get_serialNumber"
        _get_serialNumber :: Ptr X509_ -> IO (Ptr ASN1_INTEGER)

foreign import ccall unsafe "X509_get_issuer_name"
        _get_issuer_name :: Ptr X509_ -> IO (Ptr X509_NAME)

foreign import ccall unsafe "X509_get_subject_name"
        _get_subject_name :: Ptr X509_ -> IO (Ptr X509_NAME)

foreign import ccall unsafe "HsOpenSSL_X509_get_notBefore"
        _get_notBefore :: Ptr X509_ -> IO (Ptr ASN1_TIME)

foreign import ccall unsafe "HsOpenSSL_X509_get_notAfter"
        _get_notAfter :: Ptr X509_ -> IO (Ptr ASN1_TIME)

foreign import ccall unsafe "X509_get_pubkey"
        _get_pubkey :: Ptr X509_ -> IO (Ptr EVP_PKEY)

foreign import ccall unsafe "X509_get1_email"
        _get1_email :: Ptr X509_ -> IO (Ptr STACK)

foreign import ccall unsafe "X509_email_free"
        _email_free :: Ptr STACK -> IO ()


wrapX509 :: Ptr X509_ -> IO X509
wrapX509 = newForeignPtr _free


getVersion :: X509 -> IO Int
getVersion x509
    = withForeignPtr x509 $ \ x509Ptr ->
      liftM fromIntegral $ _get_version x509Ptr


getSerialNumber :: X509 -> IO Integer
getSerialNumber x509
    = withForeignPtr x509 $ \ x509Ptr ->
      _get_serialNumber x509Ptr
           >>= peekASN1Integer


getIssuerName :: X509 -> Bool -> IO [(String, String)]
getIssuerName x509 wantLongName
    = withForeignPtr x509 $ \ x509Ptr ->
      do namePtr <- _get_issuer_name x509Ptr
         peekX509Name namePtr wantLongName


getSubjectName :: X509 -> Bool -> IO [(String, String)]
getSubjectName x509 wantLongName
    = withForeignPtr x509 $ \ x509Ptr ->
      do namePtr <- _get_subject_name x509Ptr
         peekX509Name namePtr wantLongName


getNotBefore :: X509 -> IO String
getNotBefore x509
    = withForeignPtr x509 $ \ x509Ptr ->
      _get_notBefore x509Ptr
           >>= peekASN1Time


getNotAfter :: X509 -> IO String
getNotAfter x509
    = withForeignPtr x509 $ \ x509Ptr ->
      _get_notAfter x509Ptr
           >>= peekASN1Time


getPublicKey :: X509 -> IO EvpPKey
getPublicKey x509
    = withForeignPtr x509 $ \ x509Ptr ->
      _get_pubkey x509Ptr
           >>= failIfNull
           >>= wrapPKey


getEmail :: X509 -> IO [String]
getEmail x509
    = withForeignPtr x509 $ \ x509Ptr ->
      do st   <- _get1_email x509Ptr
         list <- mapStack peekCString st
         _email_free st
         return list