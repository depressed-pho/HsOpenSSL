{- -*- haskell -*- -}

-- This module is private. Please don't use this directly.

module OpenSSL.BN
    ( BigNum
    , BIGNUM

    , bn2dec
    )
    where

import           Control.Monad
import           Foreign
import           Foreign.C

#include "HsOpenSSL.h"

type BigNum = Ptr BIGNUM
data BIGNUM = BIGNUM


foreign import ccall unsafe "BN_bn2dec"
        _bn2dec :: BigNum -> IO CString

foreign import ccall unsafe "HsOpenSSL_OPENSSL_free"
        _openssl_free :: Ptr a -> IO ()



bn2dec :: BigNum -> IO Integer
bn2dec bn
    = do strPtr <- _bn2dec bn
         when (strPtr == nullPtr) $ fail "BN_bn2dec failed"
         
         str <- peekCString strPtr
         _openssl_free strPtr

         return $ read str
