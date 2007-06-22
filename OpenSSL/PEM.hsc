{- -*- haskell -*- -}
module OpenSSL.PEM
    ( PemPasswordRWState(..)
    , PemPasswordSupply(..)

    , writePKCS8PrivateKey
    , readPrivateKey

    , writePublicKey
    , readPublicKey

    , writeX509
    , readX509

    , writeX509Req
    , readX509Req
    )
    where

#include "HsOpenSSL.h"

import           Control.Exception
import           Control.Monad
import           Foreign
import           Foreign.C
import           OpenSSL.BIO
import           OpenSSL.EVP.Cipher
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils
import           OpenSSL.X509
import           OpenSSL.X509.Request
import           Prelude hiding (catch)
import           System.IO


type PemPasswordCallback = Ptr CChar -> Int -> Int -> Ptr () -> IO Int

data PemPasswordRWState = PwRead
                        | PwWrite

-- FIXME: using PwTTY causes an error but I don't know why.
-- error:0906406D:PEM routines:DEF_CALLBACK:problems getting password
data PemPasswordSupply = PwNone
                       | PwStr String
                       | PwCallback (Int -> PemPasswordRWState -> IO String)
                       | PwTTY

foreign import ccall "wrapper"
        mkPemPasswordCallback :: PemPasswordCallback -> IO (FunPtr PemPasswordCallback)


rwflagToState :: Int -> PemPasswordRWState
rwflagToState 0 = PwRead
rwflagToState 1 = PwWrite


callPasswordCB :: (Int -> PemPasswordRWState -> IO String) -> PemPasswordCallback
callPasswordCB cb buf bufLen rwflag _
    = let mode = rwflagToState rwflag
          try  = do passStr <- cb bufLen mode
                    let passLen = length passStr

                    when (passLen > bufLen)
                         $ failForTooLongPassword bufLen

                    pokeArray buf $ map (toEnum . fromEnum) passStr
                    return passLen
      in
        try `catch` \ exc ->
            do hPutStrLn stderr $ show exc
               return 0 -- zero indicates an error
    where
      failForTooLongPassword :: Int -> IO a
      failForTooLongPassword len
          = fail ("callPasswordCB: the password which the callback returned is too long: "
                  ++ "it must be at most " ++ show len ++ " bytes.")


{- PKCS#8 -------------------------------------------------------------------- -}

foreign import ccall safe "PEM_write_bio_PKCS8PrivateKey"
        _write_bio_PKCS8PrivateKey :: Ptr BIO_
                                   -> Ptr EVP_PKEY
                                   -> Ptr EVP_CIPHER
                                   -> Ptr CChar
                                   -> Int
                                   -> FunPtr PemPasswordCallback
                                   -> Ptr a
                                   -> IO Int

writePKCS8PrivateKey' :: BIO
                      -> EvpPKey
                      -> Maybe (EvpCipher, PemPasswordSupply)
                      -> IO ()
writePKCS8PrivateKey' bio pkey encryption
    = withForeignPtr bio  $ \ bioPtr  ->
      withForeignPtr pkey $ \ pkeyPtr ->
      do ret <- case encryption of
                  Nothing
                      -> _write_bio_PKCS8PrivateKey bioPtr pkeyPtr nullPtr nullPtr 0 nullFunPtr nullPtr

                  Just (_, PwNone)
                      -> _write_bio_PKCS8PrivateKey bioPtr pkeyPtr nullPtr nullPtr 0 nullFunPtr nullPtr

                  Just (cipher, PwStr passStr)
                      -> withCStringLen passStr $ \ (passPtr, passLen) ->
                         _write_bio_PKCS8PrivateKey bioPtr pkeyPtr cipher passPtr passLen nullFunPtr nullPtr

                  Just (cipher, PwCallback cb)
                      -> do cbPtr <- mkPemPasswordCallback $ callPasswordCB cb
                            ret   <- _write_bio_PKCS8PrivateKey bioPtr pkeyPtr cipher nullPtr 0 cbPtr nullPtr
                            freeHaskellFunPtr cbPtr
                            return ret
               
                  Just (cipher, PwTTY)
                      -> _write_bio_PKCS8PrivateKey bioPtr pkeyPtr cipher nullPtr 0 nullFunPtr nullPtr
         failIf (/= 1) ret
         return ()


writePKCS8PrivateKey :: EvpPKey -> Maybe (EvpCipher, PemPasswordSupply) -> IO String
writePKCS8PrivateKey pkey encryption
    = do mem <- newMem
         writePKCS8PrivateKey' mem pkey encryption
         bioRead mem


foreign import ccall safe "PEM_read_bio_PrivateKey"
        _read_bio_PrivateKey :: Ptr BIO_
                             -> Ptr (Ptr EVP_PKEY)
                             -> FunPtr PemPasswordCallback
                             -> Ptr ()
                             -> IO (Ptr EVP_PKEY)

readPrivateKey' :: BIO -> PemPasswordSupply -> IO EvpPKey
readPrivateKey' bio supply
    = withForeignPtr bio $ \ bioPtr ->
      do pkeyPtr <- case supply of
                      PwNone
                          -> withCString "" $ \ strPtr ->
                             _read_bio_PrivateKey bioPtr nullPtr nullFunPtr (unsafeCoercePtr strPtr)
                                
                      PwStr passStr
                          -> do cbPtr <- mkPemPasswordCallback $
                                         callPasswordCB $ \ _ _ ->
                                         return passStr
                                pkeyPtr <- _read_bio_PrivateKey bioPtr nullPtr cbPtr nullPtr 
                                freeHaskellFunPtr cbPtr
                                return pkeyPtr
                      PwCallback cb
                          -> do cbPtr <- mkPemPasswordCallback $ callPasswordCB cb
                                pkeyPtr <- _read_bio_PrivateKey bioPtr nullPtr cbPtr nullPtr 
                                freeHaskellFunPtr cbPtr
                                return pkeyPtr
                      PwTTY
                          -> _read_bio_PrivateKey bioPtr nullPtr nullFunPtr nullPtr 
         failIfNull pkeyPtr
         wrapPKey pkeyPtr


readPrivateKey :: String -> PemPasswordSupply -> IO EvpPKey
readPrivateKey pemStr supply
    = do mem <- newConstMem pemStr
         readPrivateKey' mem supply


{- Public Key ---------------------------------------------------------------- -}

foreign import ccall unsafe "PEM_write_bio_PUBKEY"
        _write_bio_PUBKEY :: Ptr BIO_ -> Ptr EVP_PKEY -> IO Int

foreign import ccall unsafe "PEM_read_bio_PUBKEY"
        _read_bio_PUBKEY :: Ptr BIO_
                         -> Ptr (Ptr EVP_PKEY)
                         -> FunPtr PemPasswordCallback
                         -> Ptr ()
                         -> IO (Ptr EVP_PKEY)


writePublicKey' :: BIO -> EvpPKey -> IO ()
writePublicKey' bio pkey
    = withForeignPtr bio  $ \ bioPtr  ->
      withForeignPtr pkey $ \ pkeyPtr ->
      _write_bio_PUBKEY bioPtr pkeyPtr >>= failIf (/= 1) >> return ()


writePublicKey :: EvpPKey -> IO String
writePublicKey pkey
    = do mem <- newMem
         writePublicKey' mem pkey
         bioRead mem

-- Why the heck PEM_read_bio_PUBKEY takes pem_password_cb? Is there
-- any form of encrypted public key?
readPublicKey' :: BIO -> IO EvpPKey
readPublicKey' bio
    = withForeignPtr bio $ \ bioPtr ->
      withCString "" $ \ passPtr ->
      _read_bio_PUBKEY bioPtr nullPtr nullFunPtr (unsafeCoercePtr passPtr)
           >>= failIfNull
           >>= wrapPKey


readPublicKey :: String -> IO EvpPKey
readPublicKey pemStr
    = newConstMem pemStr >>= readPublicKey'


{- X.509 certificate --------------------------------------------------------- -}

foreign import ccall safe "PEM_write_bio_X509_AUX"
        _write_bio_X509_AUX :: Ptr BIO_
                            -> Ptr X509_
                            -> IO Int

foreign import ccall safe "PEM_read_bio_X509_AUX"
        _read_bio_X509_AUX :: Ptr BIO_
                           -> Ptr (Ptr X509_)
                           -> FunPtr PemPasswordCallback
                           -> Ptr ()
                           -> IO (Ptr X509_)

writeX509' :: BIO -> X509 -> IO ()
writeX509' bio x509
    = withForeignPtr bio  $ \ bioPtr  ->
      withForeignPtr x509 $ \ x509Ptr ->
      _write_bio_X509_AUX bioPtr x509Ptr
           >>= failIf (/= 1)
           >>  return ()


writeX509 :: X509 -> IO String
writeX509 x509
    = do mem <- newMem
         writeX509' mem x509
         bioRead mem


-- I believe X.509 isn't encrypted.
readX509' :: BIO -> IO X509
readX509' bio
    = withForeignPtr bio $ \ bioPtr ->
      withCString "" $ \ passPtr ->
      _read_bio_X509_AUX bioPtr nullPtr nullFunPtr (unsafeCoercePtr passPtr)
           >>= failIfNull
           >>= wrapX509


readX509 :: String -> IO X509
readX509 pemStr
    = newConstMem pemStr >>= readX509'


{- PKCS#10 certificate request ----------------------------------------------- -}

foreign import ccall safe "PEM_write_bio_X509_REQ"
        _write_bio_X509_REQ :: Ptr BIO_
                            -> Ptr X509_REQ
                            -> IO Int

foreign import ccall safe "PEM_write_bio_X509_REQ_NEW"
        _write_bio_X509_REQ_NEW :: Ptr BIO_
                                -> Ptr X509_REQ
                                -> IO Int

foreign import ccall safe "PEM_read_bio_X509_REQ"
        _read_bio_X509_REQ :: Ptr BIO_
                           -> Ptr (Ptr X509_REQ)
                           -> FunPtr PemPasswordCallback
                           -> Ptr ()
                           -> IO (Ptr X509_REQ)


writeX509Req' :: BIO -> X509Req -> Bool -> IO ()
writeX509Req' bio req new
    = withForeignPtr bio $ \ bioPtr ->
      withForeignPtr req $ \ reqPtr ->
      writer bioPtr reqPtr
                 >>= failIf (/= 1)
                 >>  return ()
    where
      writer = if new then
                   _write_bio_X509_REQ_NEW
               else
                   _write_bio_X509_REQ


writeX509Req :: X509Req -> Bool -> IO String
writeX509Req req new
    = do mem <- newMem
         writeX509Req' mem req new
         bioRead mem


readX509Req' :: BIO -> IO X509Req
readX509Req' bio
    = withForeignPtr bio $ \ bioPtr ->
      withCString "" $ \ passPtr ->
      _read_bio_X509_REQ bioPtr nullPtr nullFunPtr (unsafeCoercePtr passPtr)
           >>= failIfNull
           >>= wrapX509Req


readX509Req :: String -> IO X509Req
readX509Req pemStr
    = newConstMem pemStr >>= readX509Req'
