{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.X509.Request
    ( X509Req
    , X509_REQ
    , newX509Req
    , wrapX509Req -- private
    , withX509ReqPtr -- private

    , signX509Req
    , verifyX509Req

    , printX509Req

    , getVersion
    , setVersion

    , getSubjectName
    , setSubjectName

    , getPublicKey
    , setPublicKey

    , makeX509FromReq
    )
    where

import           Control.Monad
import           Foreign
import           Foreign.C
import           OpenSSL.BIO
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils
import           OpenSSL.X509 (X509)
import qualified OpenSSL.X509 as Cert
import           OpenSSL.X509.Name


newtype X509Req  = X509Req (ForeignPtr X509_REQ)
data    X509_REQ = X509_REQ


foreign import ccall unsafe "X509_REQ_new"
        _new :: IO (Ptr X509_REQ)

foreign import ccall unsafe "&X509_REQ_free"
        _free :: FunPtr (Ptr X509_REQ -> IO ())

foreign import ccall unsafe "X509_REQ_sign"
        _sign :: Ptr X509_REQ -> Ptr EVP_PKEY -> Ptr EVP_MD -> IO Int

foreign import ccall unsafe "X509_REQ_verify"
        _verify :: Ptr X509_REQ -> Ptr EVP_PKEY -> IO Int

foreign import ccall unsafe "X509_REQ_print"
        _print :: Ptr BIO_ -> Ptr X509_REQ -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_REQ_get_version"
        _get_version :: Ptr X509_REQ -> IO CLong

foreign import ccall unsafe "X509_REQ_set_version"
        _set_version :: Ptr X509_REQ -> CLong -> IO Int

foreign import ccall unsafe "HsOpenSSL_X509_REQ_get_subject_name"
        _get_subject_name :: Ptr X509_REQ -> IO (Ptr X509_NAME)

foreign import ccall unsafe "X509_REQ_set_subject_name"
        _set_subject_name :: Ptr X509_REQ -> Ptr X509_NAME -> IO Int

foreign import ccall unsafe "X509_REQ_get_pubkey"
        _get_pubkey :: Ptr X509_REQ -> IO (Ptr EVP_PKEY)

foreign import ccall unsafe "X509_REQ_set_pubkey"
        _set_pubkey :: Ptr X509_REQ -> Ptr EVP_PKEY -> IO Int


newX509Req :: IO X509Req
newX509Req = _new >>= wrapX509Req


wrapX509Req :: Ptr X509_REQ -> IO X509Req
wrapX509Req reqPtr = newForeignPtr _free reqPtr >>= return . X509Req


withX509ReqPtr :: X509Req -> (Ptr X509_REQ -> IO a) -> IO a
withX509ReqPtr (X509Req req) = withForeignPtr req


signX509Req :: X509Req -> EvpPKey -> Maybe EvpMD -> IO ()
signX509Req req pkey mDigest
    = withX509ReqPtr req  $ \ reqPtr  ->
      withPKeyPtr    pkey $ \ pkeyPtr ->
      do digest <- case mDigest of
                     Just md -> return md
                     Nothing -> pkeyDefaultMD pkey
         withMDPtr digest $ \ digestPtr ->
             _sign reqPtr pkeyPtr digestPtr
                  >>= failIf (== 0)
         return ()


verifyX509Req :: X509Req -> EvpPKey -> IO Bool
verifyX509Req req pkey
    = withX509ReqPtr req  $ \ reqPtr  ->
      withPKeyPtr    pkey $ \ pkeyPtr ->
      _verify reqPtr pkeyPtr
           >>= interpret
    where
      interpret :: Int -> IO Bool
      interpret 1 = return True
      interpret 0 = return False
      interpret _ = raiseOpenSSLError


printX509Req :: X509Req -> IO String
printX509Req req
    = do mem <- newMem
         withBioPtr mem $ \ memPtr ->
             withX509ReqPtr req $ \ reqPtr ->
                 _print memPtr reqPtr
                      >>= failIf (/= 1)
         bioRead mem


getVersion :: X509Req -> IO Int
getVersion req
    = withX509ReqPtr req $ \ reqPtr ->
      liftM fromIntegral $ _get_version reqPtr


setVersion :: X509Req -> Int -> IO ()
setVersion req ver
    = withX509ReqPtr req $ \ reqPtr ->
      _set_version reqPtr (fromIntegral ver)
           >>= failIf (/= 1)
           >>  return ()


getSubjectName :: X509Req -> Bool -> IO [(String, String)]
getSubjectName req wantLongName
    = withX509ReqPtr req $ \ reqPtr ->
      do namePtr <- _get_subject_name reqPtr
         peekX509Name namePtr wantLongName


setSubjectName :: X509Req -> [(String, String)] -> IO ()
setSubjectName req subject
    = withX509ReqPtr req $ \ reqPtr ->
      withX509Name subject $ \ namePtr ->
      _set_subject_name reqPtr namePtr
           >>= failIf (/= 1)
           >>  return ()


getPublicKey :: X509Req -> IO EvpPKey
getPublicKey req
    = withX509ReqPtr req $ \ reqPtr ->
      _get_pubkey reqPtr
           >>= failIfNull
           >>= wrapPKeyPtr


setPublicKey :: X509Req -> EvpPKey -> IO ()
setPublicKey req pkey
    = withX509ReqPtr req  $ \ reqPtr  ->
      withPKeyPtr    pkey $ \ pkeyPtr ->
      _set_pubkey reqPtr pkeyPtr
           >>= failIf (/= 1)
           >>  return ()


-- FIXME: この函數で作った X509 は署名されてゐないし色々と情報が抜けて
-- ゐる事をドキュメントで警告する。ちゃんとした X509 を作るサンプルコー
-- ドも書く。
makeX509FromReq :: X509Req
                -> X509
                -> IO X509
makeX509FromReq req caCert
    = do reqPubKey <- getPublicKey req
         verified  <- verifyX509Req req reqPubKey

         unless verified
                    $ fail "makeX509FromReq: the request isn't properly signed by its own key."

         cert <- Cert.newX509
         Cert.setVersion cert 2 -- Version 2 means X509 v3. It's confusing.
         Cert.setIssuerName  cert =<< Cert.getSubjectName caCert False
         Cert.setSubjectName cert =<< getSubjectName req False
         Cert.setPublicKey   cert =<< getPublicKey req

         return cert