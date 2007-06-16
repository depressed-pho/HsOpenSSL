{- -*- haskell -*- -}
module OpenSSL.PEM
    ( PemPasswordRWState(..)
    , PemPasswordSupply(..)

    , writePKCS8PrivateKey
    , writePKCS8PrivateKeyToString
    , readPrivateKey
    , readPrivateKeyFromString

    , writePublicKey
    , writePublicKeyToString
    , readPublicKey
    , readPublicKeyFromString
    )
    where

#include "HsOpenSSL.h"

import           Control.Exception
import           Control.Monad
import           Foreign
import           Foreign.C
import           OpenSSL.BIO as BIO
import           OpenSSL.EVP.Cipher
import           OpenSSL.EVP.PKey
import           OpenSSL.Utils
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
        _write_bio_PKCS8PrivateKey :: Ptr BIO_       ->
                                      Ptr EVP_PKEY   ->
                                      Ptr EVP_CIPHER ->
                                      Ptr CUChar     ->
                                      Int            ->
                                      FunPtr PemPasswordCallback ->
                                      Ptr a          ->
                                      IO Int

writePKCS8PrivateKey :: BIO
                     -> EvpPKey
                     -> Maybe (EvpCipher, PemPasswordSupply)
                     -> IO ()
writePKCS8PrivateKey bio pkey encryption
    = withForeignPtr bio  $ \ bioPtr  ->
      withForeignPtr pkey $ \ pkeyPtr ->
      do ret <- case encryption of
                  Nothing
                      -> _write_bio_PKCS8PrivateKey bioPtr pkeyPtr nullPtr nullPtr 0 nullFunPtr nullPtr

                  Just (_, PwNone)
                      -> _write_bio_PKCS8PrivateKey bioPtr pkeyPtr nullPtr nullPtr 0 nullFunPtr nullPtr

                  Just (cipher, PwStr passStr)
                      -> withCStringLen passStr $ \ (passPtr, passLen) ->
                         _write_bio_PKCS8PrivateKey bioPtr pkeyPtr cipher (unsafeCoercePtr passPtr) passLen nullFunPtr nullPtr

                  Just (cipher, PwCallback cb)
                      -> do cbPtr <- mkPemPasswordCallback $ callPasswordCB cb
                            ret   <- _write_bio_PKCS8PrivateKey bioPtr pkeyPtr cipher nullPtr 0 cbPtr nullPtr
                            freeHaskellFunPtr cbPtr
                            return ret
               
                  Just (cipher, PwTTY)
                      -> _write_bio_PKCS8PrivateKey bioPtr pkeyPtr cipher nullPtr 0 nullFunPtr nullPtr
         failIf (/= 1) ret
         return ()


writePKCS8PrivateKeyToString :: EvpPKey -> Maybe (EvpCipher, PemPasswordSupply) -> IO String
writePKCS8PrivateKeyToString pkey encryption
    = do mem <- newMemBuf
         writePKCS8PrivateKey mem pkey encryption
         BIO.read mem


foreign import ccall safe "PEM_read_bio_PrivateKey"
        _read_bio_PrivateKey :: Ptr BIO_ ->
                                Ptr (Ptr EVP_PKEY) ->
                                FunPtr PemPasswordCallback ->
                                Ptr () ->
                                IO (Ptr EVP_PKEY)

readPrivateKey :: BIO -> PemPasswordSupply -> IO EvpPKey
readPrivateKey bio supply
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


readPrivateKeyFromString :: String -> PemPasswordSupply -> IO EvpPKey
readPrivateKeyFromString pemStr supply
    = do mem <- newConstMemBuf pemStr
         readPrivateKey mem supply


{- Public Key ---------------------------------------------------------------- -}

foreign import ccall unsafe "PEM_write_bio_PUBKEY"
        _write_bio_PUBKEY :: Ptr BIO_ -> Ptr EVP_PKEY -> IO Int


writePublicKey :: BIO -> EvpPKey -> IO ()
writePublicKey bio pkey
    = withForeignPtr bio  $ \ bioPtr  ->
      withForeignPtr pkey $ \ pkeyPtr ->
      _write_bio_PUBKEY bioPtr pkeyPtr >>= failIf (/= 1) >> return ()


writePublicKeyToString :: EvpPKey -> IO String
writePublicKeyToString pkey
    = do mem <- newMemBuf
         writePublicKey mem pkey
         BIO.read mem


foreign import ccall unsafe "PEM_read_bio_PUBKEY"
        _read_bio_PUBKEY :: Ptr BIO_ ->
                            Ptr (Ptr EVP_PKEY) ->
                            FunPtr PemPasswordCallback ->
                            Ptr () ->
                            IO (Ptr EVP_PKEY)

-- Why the heck PEM_read_bio_PUBKEY takes pem_password_cb? Is there
-- any form of encrypted public key!?
readPublicKey :: BIO -> IO EvpPKey
readPublicKey bio
    = withForeignPtr bio $ \ bioPtr ->
      do cbPtr <- mkPemPasswordCallback $
                  callPasswordCB $ \ _ _ ->
                  return ""
         pkeyPtr <- _read_bio_PUBKEY bioPtr nullPtr cbPtr nullPtr
         freeHaskellFunPtr cbPtr

         failIfNull pkeyPtr
         wrapPKey pkeyPtr


readPublicKeyFromString :: String -> IO EvpPKey
readPublicKeyFromString pemStr
    = do mem <- newConstMemBuf pemStr
         readPublicKey mem
