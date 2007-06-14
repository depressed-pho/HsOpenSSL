{- -*- haskell -*- -}

-- This module is private. Please don't use this directly.

module OpenSSL.BN
    ( BigNum(..)

    , bn2dec
    )
    where

import           Control.Monad
import           Foreign
import           Foreign.C

#include "HsOpenSSL.h"

newtype BigNum     = BigNum (Ptr ())
type    BigNum_ptr = Ptr ()


foreign import ccall unsafe "BN_bn2dec"
        _bn2dec :: BigNum_ptr -> IO CString

foreign import ccall unsafe "HsOpenSSL_OPENSSL_free"
        _openssl_free :: Ptr a -> IO ()



bn2dec :: BigNum -> IO Integer
bn2dec (BigNum bnPtr)
    = do strPtr <- _bn2dec bnPtr
         when (strPtr == nullPtr) $ fail "BN_bn2dec failed"
         
         str <- peekCString strPtr
         _openssl_free strPtr

         return $ read str
