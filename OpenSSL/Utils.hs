{- -*- haskell -*- -}

-- #hide

module OpenSSL.Utils
    ( failIfNull
    , failIf
    , raiseOpenSSLError

    , unsafeCoercePtr

    , withForeignPtrM
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


withForeignPtrM :: Maybe (ForeignPtr a) -> (Ptr a -> IO b) -> IO b
withForeignPtrM Nothing   f = f nullPtr
withForeignPtrM (Just fp) f = withForeignPtr fp f
