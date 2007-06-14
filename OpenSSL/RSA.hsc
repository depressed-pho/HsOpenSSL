{- -*- haskell -*- -}
module OpenSSL.RSA
    ( RSA

    , generateKey

    , rsaN
    , rsaE
    , rsaD
    , rsaP
    , rsaQ
    , rsaDMP1
    , rsaDMQ1
    , rsaIQMP
    )
    where

#include "HsOpenSSL.h"

import           Control.Monad
import           Foreign
import           Foreign.C
import           OpenSSL.BN
import           OpenSSL.Utils


newtype RSA     = RSA (ForeignPtr ())
type    RSA_ptr = Ptr ()


foreign import ccall unsafe "&RSA_free"
        _free :: FunPtr (RSA_ptr -> IO ())


{- generation --------------------------------------------------------------- -}

type GenKeyCallback = Int -> Int -> Ptr () -> IO ()


foreign import ccall unsafe "wrapper"
        mkGenKeyCallback :: GenKeyCallback -> IO (FunPtr GenKeyCallback)

foreign import ccall safe "RSA_generate_key"
        _generate_key :: Int -> Int -> FunPtr GenKeyCallback -> Ptr () -> IO RSA_ptr


generateKey :: Int -> Int -> Maybe (Int -> Int -> IO ()) -> IO RSA

generateKey nbits e Nothing
    = do ptr <- _generate_key nbits e nullFunPtr nullPtr
         failIfNull ptr
         liftM RSA $ newForeignPtr _free ptr

generateKey nbits e (Just cb)
    = do cbPtr <- mkGenKeyCallback
                  $ \ arg1 arg2 _ -> cb arg1 arg2
         ptr   <- _generate_key nbits e cbPtr nullPtr
         freeHaskellFunPtr cbPtr
         failIfNull ptr
         liftM RSA $ newForeignPtr _free ptr


{- exploration -------------------------------------------------------------- -}

peekRSAPublic :: (Ptr () -> IO (Ptr ())) -> RSA -> IO Integer
peekRSAPublic peeker (RSA rsa)
    = withForeignPtr rsa $ \ rsaPtr ->
      do bnPtr <- peeker rsaPtr
         when (bnPtr == nullPtr) $ fail "peekRSAPublic: got a nullPtr"
         bn2dec $ BigNum bnPtr


peekRSAPrivate :: (Ptr () -> IO (Ptr ())) -> RSA -> IO (Maybe Integer)
peekRSAPrivate peeker (RSA rsa)
    = withForeignPtr rsa $ \ rsaPtr ->
      do bnPtr <- peeker rsaPtr
         if bnPtr == nullPtr then
             return Nothing
           else
             bn2dec (BigNum bnPtr) >>= return . Just


rsaN :: RSA -> IO Integer
rsaN = peekRSAPublic (#peek RSA, n)

rsaE :: RSA -> IO Integer
rsaE = peekRSAPublic (#peek RSA, e)

rsaD :: RSA -> IO (Maybe Integer)
rsaD = peekRSAPrivate (#peek RSA, d)

rsaP :: RSA -> IO (Maybe Integer)
rsaP = peekRSAPrivate (#peek RSA, p)

rsaQ :: RSA -> IO (Maybe Integer)
rsaQ = peekRSAPrivate (#peek RSA, q)

rsaDMP1 :: RSA -> IO (Maybe Integer)
rsaDMP1 = peekRSAPrivate (#peek RSA, dmp1)

rsaDMQ1 :: RSA -> IO (Maybe Integer)
rsaDMQ1 = peekRSAPrivate (#peek RSA, dmq1)

rsaIQMP :: RSA -> IO (Maybe Integer)
rsaIQMP = peekRSAPrivate (#peek RSA, iqmp)