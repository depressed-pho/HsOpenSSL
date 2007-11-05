{- -*- haskell -*- -}

-- #prune

-- |An interface to asymmetric cipher keypair.

#include "HsOpenSSL.h"

module OpenSSL.EVP.PKey
    ( PKey
    , EVP_PKEY -- private

    , wrapPKeyPtr -- private
    , withPKeyPtr -- private
    , unsafePKeyToPtr -- private
    , touchPKey -- private
    , pkeySize -- private
    , pkeyDefaultMD -- private

      -- FIXME: newPKeyDSA, newPKeyDH and newPKeyECKey may be needed
#ifndef OPENSSL_NO_RSA
    , newPKeyRSA
#endif
#ifndef OPENSSL_NO_DSA
    , newPKeyDSA
#endif
    )
    where

import           Foreign
import           OpenSSL.DSA
import           OpenSSL.EVP.Digest hiding (digest)
import           OpenSSL.RSA
import           OpenSSL.Utils

-- |@PKey@ is an opaque object that represents either public key or
-- public\/private keypair. The concrete algorithm of asymmetric
-- cipher is hidden in the object.
newtype PKey     = PKey (ForeignPtr EVP_PKEY)
data    EVP_PKEY


foreign import ccall unsafe "EVP_PKEY_new"
        _pkey_new :: IO (Ptr EVP_PKEY)

foreign import ccall unsafe "&EVP_PKEY_free"
        _pkey_free :: FunPtr (Ptr EVP_PKEY -> IO ())

foreign import ccall unsafe "EVP_PKEY_size"
        _pkey_size :: Ptr EVP_PKEY -> IO Int


wrapPKeyPtr :: Ptr EVP_PKEY -> IO PKey
wrapPKeyPtr pkeyPtr
    = newForeignPtr _pkey_free pkeyPtr >>= return . PKey


withPKeyPtr :: PKey -> (Ptr EVP_PKEY -> IO a) -> IO a
withPKeyPtr (PKey pkey) = withForeignPtr pkey


unsafePKeyToPtr :: PKey -> Ptr EVP_PKEY
unsafePKeyToPtr (PKey pkey) = unsafeForeignPtrToPtr pkey


touchPKey :: PKey -> IO ()
touchPKey (PKey pkey) = touchForeignPtr pkey


pkeySize :: PKey -> IO Int
pkeySize pkey
    = withPKeyPtr pkey $ \ pkeyPtr ->
      _pkey_size pkeyPtr


pkeyDefaultMD :: PKey -> IO Digest
pkeyDefaultMD pkey
    = withPKeyPtr pkey $ \ pkeyPtr ->
      do pkeyType   <- (#peek EVP_PKEY, type) pkeyPtr :: IO Int
         digestName <- case pkeyType of
#ifndef OPENSSL_NO_RSA
                         (#const EVP_PKEY_RSA) -> return "sha1"
#endif
#ifndef OPENSSLNO_DSA
                         (#const EVP_PKEY_DSA) -> return "dss1"
#endif
                         _ -> fail ("pkeyDefaultMD: unsupported pkey type: " ++ show pkeyType)
         mDigest <- getDigestByName digestName
         case mDigest of
           Just digest -> return digest
           Nothing     -> fail ("pkeyDefaultMD: digest method not found: " ++ digestName)


#ifndef OPENSSL_NO_RSA
foreign import ccall unsafe "EVP_PKEY_set1_RSA"
        _set1_RSA :: Ptr EVP_PKEY -> Ptr RSA_ -> IO Int

-- |@'newPKeyRSA' rsa@ encapsulates an RSA key into 'PKey'.
newPKeyRSA :: RSA -> PKey
newPKeyRSA rsa
    = unsafePerformIO $
      withRSAPtr rsa $ \ rsaPtr ->
      do pkeyPtr <- _pkey_new >>= failIfNull
         _set1_RSA pkeyPtr rsaPtr >>= failIf (/= 1)
         wrapPKeyPtr pkeyPtr
#endif


#ifndef OPENSSL_NO_DSA
foreign import ccall unsafe "EVP_PKEY_set1_DSA"
        _set1_DSA :: Ptr EVP_PKEY -> Ptr DSA_ -> IO Int

-- |@'newPKeyDSA' dsa@ encapsulates an 'DSA' key into 'PKey'.
newPKeyDSA :: DSA -> PKey
newPKeyDSA dsa
    = unsafePerformIO $
      withDSAPtr dsa $ \ dsaPtr ->
      do pkeyPtr <- _pkey_new >>= failIfNull
         _set1_DSA pkeyPtr dsaPtr >>= failIf (/= 1)
         wrapPKeyPtr pkeyPtr
#endif