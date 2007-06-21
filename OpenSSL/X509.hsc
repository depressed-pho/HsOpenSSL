{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.X509
    ( X509
    , X509_
    , newX509
    , wrapX509 -- private

    , signX509
    , verifyX509
    , printX509

    , getVersion
    , setVersion

    , getSerialNumber
    , setSerialNumber

    , getIssuerName
    , setIssuerName

    , getSubjectName
    , setSubjectName

    , getNotBefore
    , setNotBefore

    , getNotAfter
    , setNotAfter

    , getPublicKey
    , setPublicKey

    , getSubjectEmail
    )
    where

import           Control.Monad
import           Data.Time.Clock
import           Foreign
import           Foreign.C
import           OpenSSL.BIO
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils
import           OpenSSL.Objects
import           OpenSSL.Stack
import           OpenSSL.X509.Name


{- X509 ---------------------------------------------------------------------- -}

type X509  = ForeignPtr X509_
data X509_ = X509_


foreign import ccall unsafe "X509_new"
        _new :: IO (Ptr X509_)

foreign import ccall unsafe "&X509_free"
        _free :: FunPtr (Ptr X509_ -> IO ())

foreign import ccall unsafe "X509_print"
        _print :: Ptr BIO_ -> Ptr X509_ -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_get_version"
        _get_version :: Ptr X509_ -> IO CLong

foreign import ccall unsafe "X509_set_version"
        _set_version :: Ptr X509_ -> CLong -> IO Int

foreign import ccall unsafe "X509_get_serialNumber"
        _get_serialNumber :: Ptr X509_ -> IO (Ptr ASN1_INTEGER)

foreign import ccall unsafe "X509_set_serialNumber"
        _set_serialNumber :: Ptr X509_ -> Ptr ASN1_INTEGER -> IO Int

foreign import ccall unsafe "X509_get_issuer_name"
        _get_issuer_name :: Ptr X509_ -> IO (Ptr X509_NAME)

foreign import ccall unsafe "X509_set_issuer_name"
        _set_issuer_name :: Ptr X509_ -> Ptr X509_NAME -> IO Int

foreign import ccall unsafe "X509_get_subject_name"
        _get_subject_name :: Ptr X509_ -> IO (Ptr X509_NAME)

foreign import ccall unsafe "X509_set_subject_name"
        _set_subject_name :: Ptr X509_ -> Ptr X509_NAME -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_get_notBefore"
        _get_notBefore :: Ptr X509_ -> IO (Ptr ASN1_TIME)

foreign import ccall unsafe "X509_set_notBefore"
        _set_notBefore :: Ptr X509_ -> Ptr ASN1_TIME -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_get_notAfter"
        _get_notAfter :: Ptr X509_ -> IO (Ptr ASN1_TIME)

foreign import ccall unsafe "X509_set_notAfter"
        _set_notAfter :: Ptr X509_ -> Ptr ASN1_TIME -> IO Int

foreign import ccall unsafe "X509_get_pubkey"
        _get_pubkey :: Ptr X509_ -> IO (Ptr EVP_PKEY)

foreign import ccall unsafe "X509_set_pubkey"
        _set_pubkey :: Ptr X509_ -> Ptr EVP_PKEY -> IO Int

foreign import ccall unsafe "X509_get1_email"
        _get1_email :: Ptr X509_ -> IO (Ptr STACK)

foreign import ccall unsafe "X509_email_free"
        _email_free :: Ptr STACK -> IO ()

foreign import ccall unsafe "X509_sign"
        _sign :: Ptr X509_ -> Ptr EVP_PKEY -> Ptr EVP_MD -> IO Int

foreign import ccall unsafe "X509_verify"
        _verify :: Ptr X509_ -> Ptr EVP_PKEY -> IO Int


newX509 :: IO X509
newX509 = _new >>= failIfNull >>= wrapX509


wrapX509 :: Ptr X509_ -> IO X509
wrapX509 = newForeignPtr _free


signX509 :: X509 -> EvpPKey -> Maybe EvpMD -> IO ()
signX509 x509 pkey mDigest
    = withForeignPtr x509 $ \ x509Ptr ->
      withForeignPtr pkey $ \ pkeyPtr ->
      do digest <- case mDigest of
                     Just md -> return md
                     Nothing -> pkeyDefaultMD pkey
         _sign x509Ptr pkeyPtr digest
              >>= failIf (== 0)
         return ()


verifyX509 :: X509 -> EvpPKey -> IO Bool
verifyX509 x509 pkey
    = withForeignPtr x509 $ \ x509Ptr ->
      withForeignPtr pkey $ \ pkeyPtr ->
      _verify x509Ptr pkeyPtr
           >>= interpret
    where
      interpret :: Int -> IO Bool
      interpret 1 = return True
      interpret 0 = return False
      interpret _ = raiseOpenSSLError


printX509 :: X509 -> IO String
printX509 x509
    = do mem <- newMem
         withForeignPtr x509 $ \ x509Ptr ->
             withForeignPtr mem $ \ memPtr ->
                 _print memPtr x509Ptr
                      >>= failIf (/= 1)
         bioRead mem


getVersion :: X509 -> IO Int
getVersion x509
    = withForeignPtr x509 $ \ x509Ptr ->
      liftM fromIntegral $ _get_version x509Ptr


setVersion :: X509 -> Int -> IO ()
setVersion x509 ver
    = withForeignPtr x509 $ \ x509Ptr ->
      _set_version x509Ptr (fromIntegral ver)
           >>= failIf (/= 1)
           >>  return ()


getSerialNumber :: X509 -> IO Integer
getSerialNumber x509
    = withForeignPtr x509 $ \ x509Ptr ->
      _get_serialNumber x509Ptr
           >>= peekASN1Integer


setSerialNumber :: X509 -> Integer -> IO ()
setSerialNumber x509 serial
    = withForeignPtr x509 $ \ x509Ptr ->
      withASN1Integer serial $ \ serialPtr ->
      _set_serialNumber x509Ptr serialPtr
           >>= failIf (/= 1)
           >>  return ()


getIssuerName :: X509 -> Bool -> IO [(String, String)]
getIssuerName x509 wantLongName
    = withForeignPtr x509 $ \ x509Ptr ->
      do namePtr <- _get_issuer_name x509Ptr
         peekX509Name namePtr wantLongName


setIssuerName :: X509 -> [(String, String)] -> IO ()
setIssuerName x509 issuer
    = withForeignPtr x509 $ \ x509Ptr ->
      withX509Name issuer $ \ namePtr ->
      _set_issuer_name x509Ptr namePtr
           >>= failIf (/= 1)
           >>  return ()


getSubjectName :: X509 -> Bool -> IO [(String, String)]
getSubjectName x509 wantLongName
    = withForeignPtr x509 $ \ x509Ptr ->
      do namePtr <- _get_subject_name x509Ptr
         peekX509Name namePtr wantLongName


setSubjectName :: X509 -> [(String, String)] -> IO ()
setSubjectName x509 subject
    = withForeignPtr x509 $ \ x509Ptr ->
      withX509Name subject $ \ namePtr ->
      _set_subject_name x509Ptr namePtr
           >>= failIf (/= 1)
           >>  return ()


getNotBefore :: X509 -> IO UTCTime
getNotBefore x509
    = withForeignPtr x509 $ \ x509Ptr ->
      _get_notBefore x509Ptr
           >>= peekASN1Time


setNotBefore :: X509 -> UTCTime -> IO ()
setNotBefore x509 utc
    = withForeignPtr x509 $ \ x509Ptr ->
      withASN1Time utc $ \ time ->
      _set_notBefore x509Ptr time
           >>= failIf (/= 1)
           >>  return ()


getNotAfter :: X509 -> IO UTCTime
getNotAfter x509
    = withForeignPtr x509 $ \ x509Ptr ->
      _get_notAfter x509Ptr
           >>= peekASN1Time


setNotAfter :: X509 -> UTCTime -> IO ()
setNotAfter x509 utc
    = withForeignPtr x509 $ \ x509Ptr ->
      withASN1Time utc $ \ time ->
      _set_notAfter x509Ptr time
           >>= failIf (/= 1)
           >>  return ()


getPublicKey :: X509 -> IO EvpPKey
getPublicKey x509
    = withForeignPtr x509 $ \ x509Ptr ->
      _get_pubkey x509Ptr
           >>= failIfNull
           >>= wrapPKey


setPublicKey :: X509 -> EvpPKey -> IO ()
setPublicKey x509 pkey
    = withForeignPtr x509 $ \ x509Ptr ->
      withForeignPtr pkey $ \ pkeyPtr ->
      _set_pubkey x509Ptr pkeyPtr
           >>= failIf (/= 1)
           >>  return ()


getSubjectEmail :: X509 -> IO [String]
getSubjectEmail x509
    = withForeignPtr x509 $ \ x509Ptr ->
      do st   <- _get1_email x509Ptr
         list <- mapStack peekCString st
         _email_free st
         return list