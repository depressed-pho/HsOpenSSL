{- -*- haskell -*- -}
module OpenSSL.SSL
    ( loadErrorStrings
    , libraryInit
    )
    where

#include <openssl/ssl.h>

foreign import ccall unsafe "SSL_load_error_strings"
        loadErrorStrings :: IO ()

foreign import ccall unsafe "SSL_library_init"
        libraryInit :: IO ()