{- -*- haskell -*- -}

-- #hide

module OpenSSL.Utils
    ( failIfNull
    , failIf
    , raiseOpenSSLError

    , unsafeCoercePtr
    )
    where

import           Foreign
import           Foreign.C
import           GHC.Base
import           OpenSSL.ERR


failIfNull :: Ptr a -> IO (Ptr a)
failIfNull ptr
    = if ptr == nullPtr then
          raiseOpenSSLError
      else
          return ptr


failIf :: (a -> Bool) -> a -> IO a
failIf f a
    | f a       = raiseOpenSSLError
    | otherwise = return a


raiseOpenSSLError :: IO a
raiseOpenSSLError = getError >>= errorString >>= fail


unsafeCoercePtr :: Ptr a -> Ptr b
unsafeCoercePtr = unsafeCoerce#