{- -*- haskell -*- -}
module OpenSSL.Utils
    ( failIfNull
    , raiseOpenSSLError
    )
    where


import           Foreign
import           Foreign.C
import           Control.Monad

failIfNull :: Ptr a -> IO ()
failIfNull ptr = when (ptr == nullPtr) raiseOpenSSLError

raiseOpenSSLError :: IO a
raiseOpenSSLError = fail "FIXME: raiseOpenSSLError"
