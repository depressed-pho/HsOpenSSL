{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.X509.Request
    ( X509Req
    , X509_REQ
    , newX509Req
    , wrapX509Req -- private

    , signX509Req
    , verifyX509Req

    , printX509Req

    , getVersion
    , setVersion

    , getSubjectName
    , setSubjectName

    , getPublicKey
    , setPublicKey
    )
    where

import           Control.Monad
import           Foreign
import           Foreign.C
import           OpenSSL.BIO
import           OpenSSL.EVP.Digest
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils
import           OpenSSL.X509.Name


type X509Req  = ForeignPtr X509_REQ
data X509_REQ = X509_REQ


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
wrapX509Req = newForeignPtr _free


signX509Req :: X509Req -> EvpPKey -> Maybe EvpMD -> IO ()
signX509Req req pkey mDigest
    = withForeignPtr req  $ \ reqPtr  ->
      withForeignPtr pkey $ \ pkeyPtr ->
      do digest <- case mDigest of
                     Just md -> return md
                     Nothing -> pkeyDefaultMD pkey
         _sign reqPtr pkeyPtr digest
              >>= failIf (== 0)
         return ()


verifyX509Req :: X509Req -> EvpPKey -> IO Bool
verifyX509Req req pkey
    = withForeignPtr req  $ \ reqPtr  ->
      withForeignPtr pkey $ \ pkeyPtr ->
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
         withForeignPtr req $ \ reqPtr ->
             withForeignPtr mem $ \ memPtr ->
                 _print memPtr reqPtr
                      >>= failIf (/= 1)
         bioRead mem


getVersion :: X509Req -> IO Int
getVersion req
    = withForeignPtr req $ \ reqPtr ->
      liftM fromIntegral $ _get_version reqPtr


setVersion :: X509Req -> Int -> IO ()
setVersion req ver
    = withForeignPtr req $ \ reqPtr ->
      _set_version reqPtr (fromIntegral ver)
           >>= failIf (/= 1)
           >>  return ()


getSubjectName :: X509Req -> Bool -> IO [(String, String)]
getSubjectName req wantLongName
    = withForeignPtr req $ \ reqPtr ->
      do namePtr <- _get_subject_name reqPtr
         peekX509Name namePtr wantLongName


setSubjectName :: X509Req -> [(String, String)] -> IO ()
setSubjectName req subject
    = withForeignPtr req $ \ reqPtr ->
      withX509Name subject $ \ namePtr ->
      _set_subject_name reqPtr namePtr
           >>= failIf (/= 1)
           >>  return ()


getPublicKey :: X509Req -> IO EvpPKey
getPublicKey req
    = withForeignPtr req $ \ reqPtr ->
      _get_pubkey reqPtr
           >>= failIfNull
           >>= wrapPKey


setPublicKey :: X509Req -> EvpPKey -> IO ()
setPublicKey req pkey
    = withForeignPtr req  $ \ reqPtr  ->
      withForeignPtr pkey $ \ pkeyPtr ->
      _set_pubkey reqPtr pkeyPtr
           >>= failIf (/= 1)
           >>  return ()