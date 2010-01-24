{- -*- haskell -*- -}

{-# OPTIONS_HADDOCK prune #-}

-- |An interface to asymmetric cipher keypair.

#include "HsOpenSSL.h"

module OpenSSL.EVP.PKey
    ( PublicKey(..)
    , KeyPair(..)
    , SomePublicKey
    , SomeKeyPair

    -- private
    , PKey(..)
    , EVP_PKEY
    , withPKeyPtr
    , withPKeyPtr'
    , wrapPKeyPtr
    , unsafePKeyToPtr
    , touchPKey
    )
    where

import           Data.Typeable
import           Data.Maybe
import           Foreign
import           Foreign.C
import           OpenSSL.DSA
import           OpenSSL.EVP.Digest hiding (digest)
import           OpenSSL.RSA
import           OpenSSL.Utils

-- VaguePKey is a ForeignPtr to EVP_PKEY, that is either public key or
-- a ker pair. We can't tell which at compile time.
newtype VaguePKey = VaguePKey (ForeignPtr EVP_PKEY)
data    EVP_PKEY

-- Instances of class PKey can be converted back and forth to
-- VaguePKey.
class PKey k where
    -- Wrap the key (i.g. RSA) into EVP_PKEY.
    toPKey        :: k -> IO VaguePKey

    -- Extract the concrete key from the EVP_PKEY. Returns Nothing if
    -- the type mismatches.
    fromPKey      :: VaguePKey -> IO (Maybe k)

    -- Do the same as EVP_PKEY_size().
    pkeySize      :: k -> Int

    -- Return the default digesting algorithm for the key.
    pkeyDefaultMD :: k -> IO Digest

-- |Instances of this class has at least public portion of a
-- keypair. They might or might not have the private key.
class (Eq k, Typeable k, PKey k) => PublicKey k where

    -- |Wrap an arbitrary public key into polymorphic type
    -- 'SomePublicKey'.
    fromPublicKey :: k -> SomePublicKey
    fromPublicKey = SomePublicKey

    -- |Cast from the polymorphic type 'SomePublicKey' to the concrete
    -- type. Return 'Nothing' if failed.
    toPublicKey :: SomePublicKey -> Maybe k
    toPublicKey (SomePublicKey pk) = cast pk

-- |Instances of this class has both of public and private portions of
-- a keypair.
class PublicKey a => KeyPair a where

    -- |Wrap an arbitrary keypair into polymorphic type 'SomeKeyPair'.
    fromKeyPair :: a -> SomeKeyPair
    fromKeyPair = SomeKeyPair

    -- |Cast from the polymorphic type 'SomeKeyPair' to the concrete
    -- type. Return 'Nothing' if failed.
    toKeyPair :: SomeKeyPair -> Maybe a
    toKeyPair (SomeKeyPair pk) = cast pk

-- Reconstruct the concrete public-key type from an EVP_PKEY.
withConcretePubKey :: VaguePKey -> (forall k. PublicKey k => k -> IO a) -> IO a
withConcretePubKey pk f
    = withPKeyPtr pk $ \ pkeyPtr ->
          do pkeyType <- (#peek EVP_PKEY, type) pkeyPtr :: IO CInt
             case pkeyType of
#ifndef OPENSSL_NO_RSA
               (#const EVP_PKEY_RSA)
                   -> do rsaPtr   <- _get1_RSA pkeyPtr
                         Just rsa <- absorbRSAPtr rsaPtr
                         f (rsa :: RSAPubKey)
#endif
#ifndef OPENSSL_NO_DSA
               (#const EVP_PKEY_DSA)
                   -> do dsaPtr   <- _get1_DSA pkeyPtr
                         Just dsa <- absorbDSAPtr dsaPtr
                         f (dsa :: DSAPubKey)
#endif
               _   -> fail ("withConcretePubKey: unsupported EVP_PKEY type: " ++ show pkeyType)

-- Reconstruct the concrete keypair type from an EVP_PKEY.
withConcreteKeyPair :: VaguePKey -> (forall k. KeyPair k => k -> IO a) -> IO a
withConcreteKeyPair pk f
    = withPKeyPtr pk $ \ pkeyPtr ->
          do pkeyType <- (#peek EVP_PKEY, type) pkeyPtr :: IO CInt
             case pkeyType of
#ifndef OPENSSL_NO_RSA
               (#const EVP_PKEY_RSA)
                   -> do rsaPtr   <- _get1_RSA pkeyPtr
                         Just rsa <- absorbRSAPtr rsaPtr
                         f (rsa :: RSAKeyPair)
#endif
#ifndef OPENSSL_NO_DSA
               (#const EVP_PKEY_DSA)
                   -> do dsaPtr   <- _get1_DSA pkeyPtr
                         Just dsa <- absorbDSAPtr dsaPtr
                         f (dsa :: DSAKeyPair)
#endif
               _   -> fail ("withConcreteKeyPair: unsupported EVP_PKEY type: " ++ show pkeyType)


-- |This is an opaque type to hold an arbitrary public key in it. The
-- actual key type can be safelly type-casted using 'toPublicKey'.
data SomePublicKey = forall k. PublicKey k => SomePublicKey !k
    deriving Typeable

instance Eq SomePublicKey where
    (SomePublicKey a) == (SomePublicKey b)
        = case cast b of
            Just c  -> a == c
            Nothing -> False  -- different types

instance PublicKey SomePublicKey where
    fromPublicKey = id
    toPublicKey   = Just

instance PKey SomePublicKey where
    toPKey        (SomePublicKey k) = toPKey k
    pkeySize      (SomePublicKey k) = pkeySize k
    pkeyDefaultMD (SomePublicKey k) = pkeyDefaultMD k
    fromPKey pk
        = withConcretePubKey pk (return . Just . SomePublicKey)


-- |This is an opaque type to hold an arbitrary keypair in it. The
-- actual key type can be safelly type-casted using 'toKeyPair'.
data SomeKeyPair = forall k. KeyPair k => SomeKeyPair !k
    deriving Typeable

instance Eq SomeKeyPair where
    (SomeKeyPair a) == (SomeKeyPair b)
        = case cast b of
            Just c  -> a == c
            Nothing -> False

instance PublicKey SomeKeyPair where
    -- Cast the keypair to a public key, hiding its private part.
    fromPublicKey (SomeKeyPair k)
        = SomePublicKey k

    -- It's impossible to cast a public key to a keypair.
    toPublicKey _ = Nothing

instance KeyPair SomeKeyPair where
    fromKeyPair = id
    toKeyPair   = Just

instance PKey SomeKeyPair where
    toPKey        (SomeKeyPair k) = toPKey k
    pkeySize      (SomeKeyPair k) = pkeySize k
    pkeyDefaultMD (SomeKeyPair k) = pkeyDefaultMD k
    fromPKey pk
        = withConcreteKeyPair pk (return . Just . SomeKeyPair)


foreign import ccall unsafe "EVP_PKEY_new"
        _pkey_new :: IO (Ptr EVP_PKEY)

foreign import ccall unsafe "&EVP_PKEY_free"
        _pkey_free :: FunPtr (Ptr EVP_PKEY -> IO ())


wrapPKeyPtr :: Ptr EVP_PKEY -> IO VaguePKey
wrapPKeyPtr ptr
    = newForeignPtr _pkey_free ptr >>= return . VaguePKey


withPKeyPtr' :: PKey k => k -> (Ptr EVP_PKEY -> IO a) -> IO a
withPKeyPtr' k f = do pk <- toPKey k
                      withPKeyPtr pk f


withPKeyPtr :: VaguePKey -> (Ptr EVP_PKEY -> IO a) -> IO a
withPKeyPtr (VaguePKey pkey) = withForeignPtr pkey


unsafePKeyToPtr :: VaguePKey -> Ptr EVP_PKEY
unsafePKeyToPtr (VaguePKey pkey) = unsafeForeignPtrToPtr pkey


touchPKey :: VaguePKey -> IO ()
touchPKey (VaguePKey pkey) = touchForeignPtr pkey


#ifndef OPENSSL_NO_RSA
-- The resulting Ptr RSA must be freed by caller.
foreign import ccall unsafe "EVP_PKEY_get1_RSA"
        _get1_RSA :: Ptr EVP_PKEY -> IO (Ptr RSA)

foreign import ccall unsafe "EVP_PKEY_set1_RSA"
        _set1_RSA :: Ptr EVP_PKEY -> Ptr RSA -> IO CInt


rsaToPKey :: RSAKey k => k -> IO VaguePKey
rsaToPKey rsa
    = withRSAPtr rsa $ \ rsaPtr ->
      do pkeyPtr <- _pkey_new >>= failIfNull
         _set1_RSA pkeyPtr rsaPtr >>= failIf_ (/= 1)
         wrapPKeyPtr pkeyPtr

rsaFromPKey :: RSAKey k => VaguePKey -> IO (Maybe k)
rsaFromPKey pk
        = withPKeyPtr pk $ \ pkeyPtr ->
          do pkeyType <- (#peek EVP_PKEY, type) pkeyPtr :: IO CInt
             case pkeyType of
               (#const EVP_PKEY_RSA)
                   -> do rsaPtr <- _get1_RSA pkeyPtr
                         rsaM   <- absorbRSAPtr rsaPtr
                         return rsaM
               _   -> return Nothing

instance PublicKey RSAPubKey
instance PKey RSAPubKey where
    toPKey          = rsaToPKey
    fromPKey        = rsaFromPKey
    pkeySize        = rsaSize
    pkeyDefaultMD _ = return . fromJust =<< getDigestByName "sha1"

instance KeyPair RSAKeyPair
instance PublicKey RSAKeyPair
instance PKey RSAKeyPair where
    toPKey          = rsaToPKey
    fromPKey        = rsaFromPKey
    pkeySize        = rsaSize
    pkeyDefaultMD _ = return . fromJust =<< getDigestByName "sha1"
#endif


#ifndef OPENSSL_NO_DSA
foreign import ccall unsafe "EVP_PKEY_get1_DSA"
        _get1_DSA :: Ptr EVP_PKEY -> IO (Ptr DSA)

foreign import ccall unsafe "EVP_PKEY_set1_DSA"
        _set1_DSA :: Ptr EVP_PKEY -> Ptr DSA -> IO CInt

dsaToPKey :: DSAKey k => k -> IO VaguePKey
dsaToPKey dsa
    = withDSAPtr dsa $ \ dsaPtr ->
      do pkeyPtr <- _pkey_new >>= failIfNull
         _set1_DSA pkeyPtr dsaPtr >>= failIf_ (/= 1)
         wrapPKeyPtr pkeyPtr

dsaFromPKey :: DSAKey k => VaguePKey -> IO (Maybe k)
dsaFromPKey pk
        = withPKeyPtr pk $ \ pkeyPtr ->
          do pkeyType <- (#peek EVP_PKEY, type) pkeyPtr :: IO CInt
             case pkeyType of
               (#const EVP_PKEY_DSA)
                   -> do dsaPtr <- _get1_DSA pkeyPtr
                         dsaM   <- absorbDSAPtr dsaPtr
                         return dsaM
               _   -> return Nothing

instance PublicKey DSAPubKey
instance PKey DSAPubKey where
    toPKey          = dsaToPKey
    fromPKey        = dsaFromPKey
    pkeySize        = dsaSize
    pkeyDefaultMD _ = return . fromJust =<< getDigestByName "dss1"

instance KeyPair DSAKeyPair
instance PublicKey DSAKeyPair
instance PKey DSAKeyPair where
    toPKey          = dsaToPKey
    fromPKey        = dsaFromPKey
    pkeySize        = dsaSize
    pkeyDefaultMD _ = return . fromJust =<< getDigestByName "dss1"
#endif