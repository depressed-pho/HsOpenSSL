{- -*- haskell -*- -}
module OpenSSL
    ( withOpenSSL
    )
    where

import OpenSSL.SSL

withOpenSSL :: IO a -> IO a
withOpenSSL act
    = do loadErrorStrings
         libraryInit
         act
