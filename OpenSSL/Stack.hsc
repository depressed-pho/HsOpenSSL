{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.Stack
    ( STACK
    , mapStack
    )
    where

import           Foreign
import           Foreign.C
import           OpenSSL.Utils


data STACK = STACK


foreign import ccall unsafe "sk_num"
        skNum :: Ptr STACK -> IO Int

foreign import ccall unsafe "sk_value"
        skValue :: Ptr STACK -> Int -> IO (Ptr ())


mapStack :: (Ptr a -> IO b) -> Ptr STACK -> IO [b]
mapStack m st
    = do num <- skNum st
         mapM (\ i -> skValue st i >>= return . unsafeCoercePtr >>= m)
                  $ take num [0..]
