{- -*- haskell -*- -}

-- #hide

module OpenSSL.SSL
    ( loadErrorStrings
    , addAllAlgorithms
    )
    where

#include "HsOpenSSL.h"

foreign import ccall unsafe "SSL_load_error_strings"
        loadErrorStrings :: IO ()

foreign import ccall unsafe "HsOpenSSL_OpenSSL_add_all_algorithms"
        addAllAlgorithms :: IO ()
