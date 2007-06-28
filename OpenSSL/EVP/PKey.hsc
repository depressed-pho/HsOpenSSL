{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.PKey
    ( EvpPKey
    , EVP_PKEY

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
    )
    where


import           Foreign
import           Foreign.C
import           OpenSSL.EVP.Digest
import           OpenSSL.RSA
import           OpenSSL.Utils


newtype EvpPKey  = EvpPKey (ForeignPtr EVP_PKEY)
data EVP_PKEY    = EVP_PKEY


foreign import ccall unsafe "EVP_PKEY_new"
        _pkey_new :: IO (Ptr EVP_PKEY)

foreign import ccall unsafe "&EVP_PKEY_free"
        _pkey_free :: FunPtr (Ptr EVP_PKEY -> IO ())

foreign import ccall unsafe "EVP_PKEY_size"
        _pkey_size :: Ptr EVP_PKEY -> IO Int


wrapPKeyPtr :: Ptr EVP_PKEY -> IO EvpPKey
wrapPKeyPtr pkeyPtr
    = newForeignPtr _pkey_free pkeyPtr >>= return . EvpPKey


withPKeyPtr :: EvpPKey -> (Ptr EVP_PKEY -> IO a) -> IO a
withPKeyPtr (EvpPKey pkey) = withForeignPtr pkey


unsafePKeyToPtr :: EvpPKey -> Ptr EVP_PKEY
unsafePKeyToPtr (EvpPKey pkey) = unsafeForeignPtrToPtr pkey


touchPKey :: EvpPKey -> IO ()
touchPKey (EvpPKey pkey) = touchForeignPtr pkey


pkeySize :: EvpPKey -> IO Int
pkeySize pkey
    = withPKeyPtr pkey $ \ pkeyPtr ->
      _pkey_size pkeyPtr


pkeyDefaultMD :: EvpPKey -> IO EvpMD
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

newPKeyRSA :: RSA -> IO EvpPKey
newPKeyRSA rsa
    = withRSAPtr rsa $ \ rsaPtr ->
      do pkeyPtr <- _pkey_new >>= failIfNull
         _set1_RSA pkeyPtr rsaPtr >>= failIf (/= 1)
         wrapPKeyPtr pkeyPtr
#endif
