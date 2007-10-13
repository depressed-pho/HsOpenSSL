{- -*- haskell -*- -}

-- | The Digital Signature Algorithm (FIPS 186-2).
--   See <http://www.openssl.org/docs/crypto/dsa.html>

#include "HsOpenSSL.h"

module OpenSSL.DSA
    ( -- * Type
      DSA

      -- * Key and parameter generation
    , generateParameters
    , generateKey
    , generateParametersAndKey

      -- * Signing and verification
    , signDigestedData
    , verifyDigestedData

      -- * Extracting fields of DSA objects
    , dsaP
    , dsaQ
    , dsaG
    , dsaPrivate
    , dsaPublic
    , dsaToTuple
    , tupleToDSA
    ) where

import           Control.Monad
import           Foreign
import           Foreign.C (CString)
import           Foreign.C.Types
import           OpenSSL.BN
import           OpenSSL.Utils
import qualified Data.ByteString as BS

-- | The type of a DSA key, includes parameters p, q, g.
newtype DSA = DSA (ForeignPtr DSA_)

data DSA_

foreign import ccall unsafe "&DSA_free"
        _free :: FunPtr (Ptr DSA_ -> IO ())

foreign import ccall unsafe "DSA_free"
        dsa_free :: Ptr DSA_ -> IO ()

foreign import ccall unsafe "BN_free"
        _bn_free :: BigNum -> IO ()

foreign import ccall unsafe "DSA_new"
        _dsa_new :: IO (Ptr DSA_)

foreign import ccall unsafe "DSA_generate_key"
        _dsa_generate_key :: Ptr DSA_ -> IO ()

foreign import ccall unsafe "HsOpenSSL_dsa_sign"
        _dsa_sign :: Ptr DSA_ -> CString -> Int -> Ptr BigNum -> Ptr BigNum -> IO Int

foreign import ccall unsafe "HsOpenSSL_dsa_verify"
        _dsa_verify :: Ptr DSA_ -> CString -> Int -> BigNum -> BigNum -> IO Int

withDSAPtr :: DSA -> (Ptr DSA_ -> IO a) -> IO a
withDSAPtr (DSA ptr) = withForeignPtr ptr

foreign import ccall safe "DSA_generate_parameters"
        _generate_params :: Int -> Ptr CChar -> Int -> Ptr CInt -> Ptr CInt -> Ptr () -> Ptr () -> IO (Ptr DSA_)

peekDSA :: (Ptr DSA_ -> IO BigNum) -> DSA -> IO (Maybe Integer)
peekDSA peeker (DSA dsa) = do
  withForeignPtr dsa (\ptr -> do
    bn <- peeker ptr
    if bn == nullPtr
       then return Nothing
       else peekBN bn >>= return . Just)

-- | Generate DSA parameters (*not* a key, but required for a key). This is a
--   compute intensive operation. See FIPS 186-2, app 2. This agrees with the
--   test vectors given in FIP 186-2, app 5
generateParameters :: Int  -- ^ The number of bits in the generated prime: 512 <= x <= 1024
                   -> Maybe BS.ByteString  -- ^ optional seed, its length must be 20 bytes
                   -> IO (Int, Int, Integer, Integer, Integer)  -- ^ (iteration count, generator count, p, q, g)
generateParameters nbits mseed = do
  when (nbits < 512 || nbits > 1024) $ fail "Invalid DSA bit size"
  alloca (\i1 -> do
    alloca (\i2 -> do
      (\x -> case mseed of
                  Nothing -> x (nullPtr, 0)
                  Just seed -> BS.useAsCStringLen seed x) (\(seedptr, seedlen) -> do
        ptr <- _generate_params nbits seedptr seedlen i1 i2 nullPtr nullPtr
        failIfNull ptr
        itcount <- peek i1
        gencount <- peek i2
        p <- (#peek DSA, p) ptr >>= peekBN
        q <- (#peek DSA, q) ptr >>= peekBN
        g <- (#peek DSA, g) ptr >>= peekBN
        dsa_free ptr
        return (fromIntegral itcount, fromIntegral gencount, p, q, g))))

{-
-- | This function just runs the example DSA generation, as given in FIP 186-2,
--   app 5. The return values should be:
--   (105,
--    "8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210
--     eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291",
--     "c773218c737ec8ee993b4f2ded30f48edace915f",
--     "626d027839ea0a13413163a55b4cb500299d5522956cefcb3bff10f399ce2c2e71cb9de5fa24
--      babf58e5b79521925c9cc42e9f6f464b088cc572af53e6d78802"), as given at the bottom of
--    page 21
test_generateParameters = do
  let seed = BS.pack [0xd5, 0x01, 0x4e, 0x4b,
                      0x60, 0xef, 0x2b, 0xa8,
                      0xb6, 0x21, 0x1b, 0x40,
                      0x62, 0xba, 0x32, 0x24,
                      0xe0, 0x42, 0x7d, 0xd3]
  (a, b, p, q, g) <- generateParameters 512 $ Just seed
  return (a, toHex p, toHex q, g)
-}

-- | Generate a new DSA key, given valid parameters
generateKey :: Integer  -- ^ p
            -> Integer  -- ^ q
            -> Integer  -- ^ g
            -> IO DSA
generateKey p q g = do
  ptr <- _dsa_new
  newBN p >>= (#poke DSA, p) ptr
  newBN q >>= (#poke DSA, q) ptr
  newBN g >>= (#poke DSA, g) ptr
  _dsa_generate_key ptr
  newForeignPtr _free ptr >>= return . DSA

dsaP :: DSA -> IO (Maybe Integer)
dsaP = peekDSA (#peek DSA, p)

dsaQ :: DSA -> IO (Maybe Integer)
dsaQ = peekDSA (#peek DSA, q)

dsaG :: DSA -> IO (Maybe Integer)
dsaG = peekDSA (#peek DSA, g)

dsaPublic :: DSA -> IO (Maybe Integer)
dsaPublic = peekDSA (#peek DSA, pub_key)

dsaPrivate :: DSA -> IO (Maybe Integer)
dsaPrivate = peekDSA (#peek DSA, priv_key)

-- | Convert a DSA object to a tuple of its members in the order p, q, g,
--   public, private. If this is a public key, private will be Nothing
dsaToTuple :: DSA -> IO (Integer, Integer, Integer, Integer, Maybe Integer)
dsaToTuple dsa = do
  Just p <- peekDSA (#peek DSA, p) dsa
  Just q <- peekDSA (#peek DSA, q) dsa
  Just g <- peekDSA (#peek DSA, g) dsa
  Just pub <- peekDSA (#peek DSA, pub_key) dsa
  private <- peekDSA (#peek DSA, priv_key) dsa

  return (p, q, g, pub, private)

-- | Convert a tuple of members (in the same format as from dsaToTuple) into a
--   DSA object
tupleToDSA :: (Integer, Integer, Integer, Integer, Maybe Integer) -> IO DSA
tupleToDSA (p, q, g, pub, mpriv) = do
  ptr <- _dsa_new
  newBN p >>= (#poke DSA, p) ptr
  newBN q >>= (#poke DSA, q) ptr
  newBN g >>= (#poke DSA, g) ptr
  newBN pub >>= (#poke DSA, pub_key) ptr
  case mpriv of
       Just priv -> newBN priv >>= (#poke DSA, priv_key) ptr
       Nothing -> (#poke DSA, priv_key) ptr nullPtr
  newForeignPtr _free ptr >>= return . DSA

-- | A utility function to generate both the parameters and the key pair at the
--   same time. Saves serialising and deserialising the parameters too
generateParametersAndKey :: Int  -- ^ The number of bits in the generated prime: 512 <= x <= 1024
                         -> Maybe BS.ByteString  -- ^ optional seed, its length must be 20 bytes
                         -> IO DSA
generateParametersAndKey nbits mseed = do
  (\x -> case mseed of
              Nothing -> x (nullPtr, 0)
              Just seed -> BS.useAsCStringLen seed x) (\(seedptr, seedlen) -> do
    ptr <- _generate_params nbits seedptr seedlen nullPtr nullPtr nullPtr nullPtr
    failIfNull ptr
    _dsa_generate_key ptr
    newForeignPtr _free ptr >>= return . DSA)

-- | Sign pre-digested data. The DSA specs call for SHA1 to be used so, if you
--   use anything else, YMMV. Returns a pair of Integers which, together, are
--   the signature
signDigestedData :: DSA -> BS.ByteString -> IO (Integer, Integer)
signDigestedData dsa bytes = do
  BS.useAsCStringLen bytes (\(ptr, len) -> do
    alloca (\rptr -> do
      alloca (\sptr -> do
        withDSAPtr dsa (\dsaptr -> do
          _dsa_sign dsaptr ptr len rptr sptr >>= failIf (== 0)
          r <- peek rptr >>= peekBN
          peek rptr >>= _bn_free
          s <- peek sptr >>= peekBN
          peek sptr >>= _bn_free
          return (r, s)))))

-- | Verify pre-digested data given a signature.
verifyDigestedData :: DSA -> BS.ByteString -> (Integer, Integer) -> IO Bool
verifyDigestedData dsa bytes (r, s) = do
  BS.useAsCStringLen bytes (\(ptr, len) -> do
    withBN r (\bnR -> do
      withBN s (\bnS -> do
        withDSAPtr dsa (\dsaptr -> do
          _dsa_verify dsaptr ptr len bnR bnS >>= return . (== 1)))))
