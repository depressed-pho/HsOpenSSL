#include "HsOpenSSL.h"

module OpenSSL.BN
    ( BigNum
    , BIGNUM

    , allocaBN
    , withBN
    , peekBN
    , newBN

#ifdef __GLASGOW_HASKELL__
    , integerToBN
    , bnToInteger
#endif
    )
    where

import           Control.Exception
import           Foreign


#ifndef __GLASGOW_HASKELL__
import           Control.Monad
import           Foreign.C
import           OpenSSL.Utils
#else
import           Foreign.C.Types
import           Data.Word (Word32)
import           GHC.Base
import           GHC.Num
import           GHC.Prim
import           GHC.IOBase (IO(..))
#endif

type BigNum = Ptr BIGNUM
data BIGNUM = BIGNUM


foreign import ccall unsafe "BN_new"
        _new :: IO BigNum

foreign import ccall unsafe "BN_free"
        _free :: BigNum -> IO ()


allocaBN :: (BigNum -> IO a) -> IO a
allocaBN m
    = bracket _new _free m


#ifndef __GLASGOW_HASKELL__

{- slow, safe functions ----------------------------------------------------- -}

foreign import ccall unsafe "BN_bn2dec"
        _bn2dec :: BigNum -> IO CString

foreign import ccall unsafe "BN_dec2bn"
        _dec2bn :: Ptr BigNum -> CString -> IO Int

foreign import ccall unsafe "HsOpenSSL_OPENSSL_free"
        _openssl_free :: Ptr a -> IO ()

withBN :: Integer -> (BigNum -> IO a) -> IO a
withBN dec m
    = withCString (show dec) $ \ strPtr ->
      alloca $ \ bnPtr ->
      do poke bnPtr nullPtr
         _dec2bn bnPtr strPtr
              >>= failIf (== 0)
         bracket (peek bnPtr) _free m


peekBN :: BigNum -> IO Integer
peekBN bn
    = do strPtr <- _bn2dec bn
         when (strPtr == nullPtr) $ fail "BN_bn2dec failed"
         str <- peekCString strPtr
         _openssl_free strPtr

         return $ read str


-- | Return a new, alloced bignum
newBN :: Integer -> IO BigNum
newBN i = do
  withCString (show i) (\str -> do
    alloca (\bnptr -> do
      poke bnptr nullPtr
      _dec2bn bnptr str >>= failIf (== 0)
      peek bnptr))

#else

{- fast, dangerous functions ------------------------------------------------ -}

-- Both BN (the OpenSSL library) and GMP (used by GHC) use the same internal
-- representation for numbers: an array of words, least-significant first. Thus
-- we can move from Integer's to BIGNUMs very quickly: by copying in the worst
-- case and by just alloca'ing and pointing into the Integer in the fast case.
-- Note that, in the fast case, it's very important that any foreign function
-- calls be "unsafe", that is, they don't call back into Haskell. Otherwise the
-- GC could do nasty things to the data which we thought that we had a pointer
-- to

foreign import ccall unsafe "memcpy"
        _copy_in :: ByteArray## -> Ptr () -> CSize -> IO ()

foreign import ccall unsafe "memcpy"
        _copy_out :: Ptr () -> ByteArray## -> CSize -> IO ()

-- These are taken from Data.Binary's disabled fast Integer support
data ByteArray = BA  {-# UNPACK #-} !ByteArray##
data MBA       = MBA {-# UNPACK #-} !(MutableByteArray## RealWorld)

newByteArray :: Int## -> IO MBA
newByteArray sz = IO $ \s ->
  case newByteArray## sz s of { (## s', arr ##) ->
  (## s', MBA arr ##) }

freezeByteArray :: MutableByteArray## RealWorld -> IO ByteArray
freezeByteArray arr = IO $ \s ->
  case unsafeFreezeByteArray## arr s of { (## s', arr' ##) ->
  (## s', BA arr' ##) }

-- | Convert a BIGNUM to an Integer
bnToInteger :: BigNum -> IO Integer
bnToInteger bn = do
  nlimbs <- (#peek BIGNUM, top) bn :: IO CSize
  case nlimbs of
    0 -> return 0
    1 -> do (I## i) <- (#peek BIGNUM, d) bn >>= peek
            negative <- (#peek BIGNUM, neg) bn :: IO Word32
            if negative == 0
               then return $ S## i
               else return $ 0 - (S## i)
    otherwise -> do
      let (I## nlimbsi) = fromIntegral nlimbs
          (I## limbsize) = (#size unsigned long)
      (MBA arr) <- newByteArray (nlimbsi *## limbsize)
      (BA ba) <- freezeByteArray arr
      limbs <- (#peek BIGNUM, d) bn
      _copy_in ba limbs $ fromIntegral $ nlimbs * (#size unsigned long)
      negative <- (#peek BIGNUM, neg) bn :: IO Word32
      if negative == 0
         then return $ J## nlimbsi ba
         else return $ 0 - (J## nlimbsi ba)

-- | This is a GHC specific, fast conversion between Integers and OpenSSL
--   bignums. It returns a malloced BigNum.
integerToBN :: Integer -> IO BigNum
integerToBN 0 = do
  bnptr <- mallocBytes (#size BIGNUM)
  (#poke BIGNUM, d) bnptr nullPtr
  -- This is needed to give GHC enough type information
  let one :: Word32
      one = 1
      zero :: Word32
      zero = 0
  (#poke BIGNUM, flags) bnptr one
  (#poke BIGNUM, top) bnptr zero
  (#poke BIGNUM, dmax) bnptr zero
  (#poke BIGNUM, neg) bnptr zero
  return bnptr

integerToBN (S## v) = do
  bnptr <- mallocBytes (#size BIGNUM)
  limbs <- malloc :: IO (Ptr Word32)
  poke limbs $ fromIntegral $ abs $ I## v
  (#poke BIGNUM, d) bnptr limbs
  -- This is needed to give GHC enough type information since #poke just
  -- uses an offset
  let one :: Word32
      one = 1
  (#poke BIGNUM, flags) bnptr one
  (#poke BIGNUM, top) bnptr one
  (#poke BIGNUM, dmax) bnptr one
  (#poke BIGNUM, neg) bnptr (if (I## v) < 0 then one else 0)
  return bnptr

integerToBN v@(J## nlimbs_ bytearray)
  | v >= 0 = do
      let nlimbs = (I## nlimbs_)
      bnptr <- mallocBytes (#size BIGNUM)
      limbs <- mallocBytes ((#size unsigned) * nlimbs)
      (#poke BIGNUM, d) bnptr limbs
      (#poke BIGNUM, flags) bnptr (1 :: Word32)
      _copy_out limbs bytearray (fromIntegral $ (#size unsigned) * nlimbs)
      (#poke BIGNUM, top) bnptr ((fromIntegral nlimbs) :: Word32)
      (#poke BIGNUM, dmax) bnptr ((fromIntegral nlimbs) :: Word32)
      (#poke BIGNUM, neg) bnptr (0 :: Word32)
      return bnptr
  | otherwise = do bnptr <- integerToBN (0-v)
                   (#poke BIGNUM, neg) bnptr (1 :: Word32)
                   return bnptr

-- TODO: we could make a function which doesn't even allocate BN data if we
-- wanted to be very fast and dangerout. The BIGNUM could point right into the
-- Integer's data. However, I'm not sure about the semantics of the GC; which
-- might move the Integer data around.

withBN :: Integer -> (BigNum -> IO a) -> IO a
withBN dec m = bracket (integerToBN dec) _free m

peekBN :: BigNum -> IO Integer
peekBN = bnToInteger

newBN = integerToBN

#endif
