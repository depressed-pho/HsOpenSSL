{- -*- haskell -*- -}
module OpenSSL.PEM
    ( PemPasswordRWState(..)
    , PemPasswordSupply(..)

    , writePKCS8PrivateKey
    , writePKCS8PrivateKeyToString

    , writePublicKey
    , writePublicKeyToString
    )
    where

#include "HsOpenSSL.h"

import           Control.Exception
import           Control.Monad
import           Foreign
import           Foreign.C
import           OpenSSL.BIO as BIO
import           OpenSSL.EVP
import           OpenSSL.Utils
import           Prelude hiding (catch)
import           System.IO


type PemPasswordCallback = Ptr CChar -> Int -> Int -> Ptr () -> IO Int

data PemPasswordRWState = PwRead
                        | PwWrite

-- FIXME: using PwTTY causes an error but I don't know why.
-- error:0906406D:PEM routines:DEF_CALLBACK:problems getting password
data PemPasswordSupply = PwStr String
                       | PwCallback (Int -> PemPasswordRWState -> IO String)
                       | PwTTY

foreign import ccall "wrapper"
        mkPemPassordCallback :: PemPasswordCallback -> IO (FunPtr PemPasswordCallback)


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

                  Just (cipher, PwStr passStr)
                      -> withCStringLen passStr $ \ (passPtr, passLen) ->
                         _write_bio_PKCS8PrivateKey bioPtr pkeyPtr cipher (unsafeCoercePtr passPtr) passLen nullFunPtr nullPtr

                  Just (cipher, PwCallback cb)
                      -> do cbPtr <- mkPemPassordCallback $ \ buf bufLen rwflag _ ->
                                     let mode = case rwflag of
                                                  0 -> PwRead
                                                  _ -> PwWrite
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
                            ret <- _write_bio_PKCS8PrivateKey bioPtr pkeyPtr cipher nullPtr 0 cbPtr nullPtr
                            freeHaskellFunPtr cbPtr
                            return ret
               
                  Just (cipher, PwTTY)
                      -> _write_bio_PKCS8PrivateKey bioPtr pkeyPtr cipher nullPtr 0 nullFunPtr nullPtr
         failIf (/= 1) ret
         return ()
    where
      failForTooLongPassword :: Int -> IO a
      failForTooLongPassword len
          = fail ("writePKCS8PrivateKey: the password which the callback returned is too long: "
                  ++ "it must be at most " ++ show len ++ " bytes.")


writePKCS8PrivateKeyToString :: EvpPKey -> Maybe (EvpCipher, PemPasswordSupply) -> IO String
writePKCS8PrivateKeyToString pkey encryption
    = do mem <- newMemBuf
         writePKCS8PrivateKey mem pkey encryption
         BIO.read mem



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
