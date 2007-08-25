module OpenSSL.BN
    ( BigNum
    , BIGNUM

    , allocaBN
    , withBN
    , peekBN
    )
    where

import           Control.Exception
import           Control.Monad
import           Foreign
import           Foreign.C
import           OpenSSL.Utils


type BigNum = Ptr BIGNUM
data BIGNUM = BIGNUM


foreign import ccall unsafe "BN_new"
        _new :: IO BigNum

foreign import ccall unsafe "BN_free"
        _free :: BigNum -> IO ()

foreign import ccall unsafe "BN_bn2dec"
        _bn2dec :: BigNum -> IO CString

foreign import ccall unsafe "BN_dec2bn"
        _dec2bn :: Ptr BigNum -> CString -> IO Int

foreign import ccall unsafe "HsOpenSSL_OPENSSL_free"
        _openssl_free :: Ptr a -> IO ()


allocaBN :: (BigNum -> IO a) -> IO a
allocaBN m
    = bracket _new _free m


withBN :: Integer -> (BigNum -> IO a) -> IO a
withBN dec m
    = withCString (show dec) $ \ strPtr ->
      alloca $ \ bnPtr ->
      do _dec2bn bnPtr strPtr
              >>= failIf (== 0)
         bracket (peek bnPtr) _free m


peekBN :: BigNum -> IO Integer
peekBN bn
    = do strPtr <- _bn2dec bn
         when (strPtr == nullPtr) $ fail "BN_bn2dec failed"
         
         str <- peekCString strPtr
         _openssl_free strPtr

         return $ read str
