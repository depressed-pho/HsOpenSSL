{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.X509.Revocation
    ( CRL
    , X509_CRL
    , RevokedCertificate(..)
    , newCRL
    , wrapCRL -- private

    , signCRL
    , verifyCRL

    , printCRL

    , getVersion
    , setVersion

    , getLastUpdate
    , setLastUpdate

    , getNextUpdate
    , setNextUpdate

    , getIssuerName
    , setIssuerName

    , getRevokedList
    , addRevoked
    , sortCRL
    )
    where

import           Control.Monad
import           Data.Time.Clock
import           Data.Typeable
import           Foreign
import           Foreign.C
import           OpenSSL.ASN1
import           OpenSSL.BIO
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.Stack
import           OpenSSL.Utils
import           OpenSSL.X509.Name


type CRL      = ForeignPtr X509_CRL
data X509_CRL = X509_CRL

data X509_REVOKED = X509_REVOKED

data RevokedCertificate
    = RevokedCertificate {
        revSerialNumber   :: Integer
      , revRevocationDate :: UTCTime
      }
    deriving (Show, Eq, Typeable)


foreign import ccall unsafe "X509_CRL_new"
        _new :: IO (Ptr X509_CRL)

foreign import ccall unsafe "&X509_CRL_free"
        _free :: FunPtr (Ptr X509_CRL -> IO ())

foreign import ccall unsafe "X509_CRL_sign"
        _sign :: Ptr X509_CRL -> Ptr EVP_PKEY -> Ptr EVP_MD -> IO Int

foreign import ccall unsafe "X509_CRL_verify"
        _verify :: Ptr X509_CRL -> Ptr EVP_PKEY -> IO Int

foreign import ccall unsafe "X509_CRL_print"
        _print :: Ptr BIO_ -> Ptr X509_CRL -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_CRL_get_version"
        _get_version :: Ptr X509_CRL -> IO CLong

foreign import ccall unsafe "X509_CRL_set_version"
        _set_version :: Ptr X509_CRL -> CLong -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_CRL_get_lastUpdate"
        _get_lastUpdate :: Ptr X509_CRL -> IO (Ptr ASN1_TIME)

foreign import ccall unsafe "X509_CRL_set_lastUpdate"
        _set_lastUpdate :: Ptr X509_CRL -> Ptr ASN1_TIME -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_CRL_get_nextUpdate"
        _get_nextUpdate :: Ptr X509_CRL -> IO (Ptr ASN1_TIME)

foreign import ccall unsafe "X509_CRL_set_nextUpdate"
        _set_nextUpdate :: Ptr X509_CRL -> Ptr ASN1_TIME -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_CRL_get_issuer"
        _get_issuer_name :: Ptr X509_CRL -> IO (Ptr X509_NAME)

foreign import ccall unsafe "X509_CRL_set_issuer_name"
        _set_issuer_name :: Ptr X509_CRL -> Ptr X509_NAME -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_CRL_get_REVOKED"
        _get_REVOKED :: Ptr X509_CRL -> IO (Ptr STACK)

foreign import ccall unsafe "X509_CRL_add0_revoked"
        _add0_revoked :: Ptr X509_CRL -> Ptr X509_REVOKED -> IO Int

foreign import ccall unsafe "X509_CRL_sort"
        _sort :: Ptr X509_CRL -> IO Int



foreign import ccall unsafe "X509_REVOKED_new"
        _new_revoked :: IO (Ptr X509_REVOKED)

foreign import ccall unsafe "X509_REVOKED_free"
        freeRevoked :: Ptr X509_REVOKED -> IO ()

foreign import ccall unsafe "X509_REVOKED_set_serialNumber"
        _set_serialNumber :: Ptr X509_REVOKED -> Ptr ASN1_INTEGER -> IO Int

foreign import ccall unsafe "X509_REVOKED_set_revocationDate"
        _set_revocationDate :: Ptr X509_REVOKED -> Ptr ASN1_TIME -> IO Int


newCRL :: IO CRL
newCRL = _new >>= wrapCRL


wrapCRL :: Ptr X509_CRL -> IO CRL
wrapCRL = newForeignPtr _free


signCRL :: CRL -> EvpPKey -> Maybe EvpMD -> IO ()
signCRL crl pkey mDigest
    = withForeignPtr crl  $ \ crlPtr  ->
      withForeignPtr pkey $ \ pkeyPtr ->
      do digest <- case mDigest of
                     Just md -> return md
                     Nothing -> pkeyDefaultMD pkey
         _sign crlPtr pkeyPtr digest
              >>= failIf (== 0)
         return ()


verifyCRL :: CRL -> EvpPKey -> IO Bool
verifyCRL crl pkey
    = withForeignPtr crl  $ \ crlPtr ->
      withForeignPtr pkey $ \ pkeyPtr ->
      _verify crlPtr pkeyPtr
           >>= interpret
    where
      interpret :: Int -> IO Bool
      interpret 1 = return True
      interpret 0 = return False
      interpret _ = raiseOpenSSLError


printCRL :: CRL -> IO String
printCRL crl
    = do mem <- newMem
         withForeignPtr mem $ \ memPtr ->
             withForeignPtr crl $ \ crlPtr ->
                 _print memPtr crlPtr
                      >>= failIf (/= 1)
         bioRead mem


getVersion :: CRL -> IO Int
getVersion crl
    = withForeignPtr crl $ \ crlPtr ->
      liftM fromIntegral $ _get_version crlPtr


setVersion :: CRL -> Int -> IO ()
setVersion crl ver
    = withForeignPtr crl $ \ crlPtr ->
      _set_version crlPtr (fromIntegral ver)
           >>= failIf (/= 1)
           >>  return ()


getLastUpdate :: CRL -> IO UTCTime
getLastUpdate crl
    = withForeignPtr crl $ \ crlPtr ->
      _get_lastUpdate crlPtr
           >>= peekASN1Time


setLastUpdate :: CRL -> UTCTime -> IO ()
setLastUpdate crl utc
    = withForeignPtr crl $ \ crlPtr ->
      withASN1Time utc $ \ time ->
      _set_lastUpdate crlPtr time
           >>= failIf (/= 1)
           >>  return ()


getNextUpdate :: CRL -> IO UTCTime
getNextUpdate crl
    = withForeignPtr crl $ \ crlPtr ->
      _get_nextUpdate crlPtr
           >>= peekASN1Time


setNextUpdate :: CRL -> UTCTime -> IO ()
setNextUpdate crl utc
    = withForeignPtr crl $ \ crlPtr ->
      withASN1Time utc $ \ time ->
      _set_nextUpdate crlPtr time
           >>= failIf (/= 1)
           >>  return ()


getIssuerName :: CRL -> Bool -> IO [(String, String)]
getIssuerName crl wantLongName
    = withForeignPtr crl $ \ crlPtr ->
      do namePtr <- _get_issuer_name crlPtr
         peekX509Name namePtr wantLongName


setIssuerName :: CRL -> [(String, String)] -> IO ()
setIssuerName crl issuer
    = withForeignPtr crl  $ \ crlPtr  ->
      withX509Name issuer $ \ namePtr ->
      _set_issuer_name crlPtr namePtr
           >>= failIf (/= 1)
           >>  return ()


getRevokedList :: CRL -> IO [RevokedCertificate]
getRevokedList crl
    = withForeignPtr crl $ \ crlPtr ->
      do stRevoked <- _get_REVOKED crlPtr
         mapStack peekRevoked stRevoked
    where
      peekRevoked :: Ptr X509_REVOKED -> IO RevokedCertificate
      peekRevoked rev
          = do serial <- peekASN1Integer =<< (#peek X509_REVOKED, serialNumber  ) rev
               date   <- peekASN1Time    =<< (#peek X509_REVOKED, revocationDate) rev
               return RevokedCertificate {
                            revSerialNumber   = serial
                          , revRevocationDate = date
                          }

newRevoked :: RevokedCertificate -> IO (Ptr X509_REVOKED)
newRevoked revoked
    = do revPtr  <- _new_revoked

         seriRet <- withASN1Integer (revSerialNumber revoked) $ \ serialPtr ->
                    _set_serialNumber revPtr serialPtr

         dateRet <- withASN1Time (revRevocationDate revoked) $ \ datePtr ->
                    _set_revocationDate revPtr datePtr

         if seriRet /= 1 || dateRet /= 1 then
             freeRevoked revPtr >> raiseOpenSSLError
           else
             return revPtr


addRevoked :: CRL -> RevokedCertificate -> IO ()
addRevoked crl revoked
    = withForeignPtr crl $ \ crlPtr ->
      do revPtr <- newRevoked revoked
         ret    <- _add0_revoked crlPtr revPtr
         case ret of
           1 -> return ()
           _ -> freeRevoked revPtr >> raiseOpenSSLError


sortCRL :: CRL -> IO ()
sortCRL crl
    = withForeignPtr crl $ \ crlPtr ->
      _sort crlPtr
           >>= failIf (/= 1)
           >>  return ()