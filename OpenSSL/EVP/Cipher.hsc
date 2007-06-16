{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Cipher
    ( EvpCipher
    , EVP_CIPHER
    , getCipherByName
    )
    where

import           Foreign
import           Foreign.C
import           OpenSSL.RSA
import           OpenSSL.Utils


{- cipher -------------------------------------------------------------------- -}

type EvpCipher  = Ptr EVP_CIPHER
data EVP_CIPHER = EVP_CIPHER


foreign import ccall unsafe "EVP_get_cipherbyname"
        _get_cipherbyname :: CString -> IO EvpCipher


getCipherByName :: String -> IO (Maybe EvpCipher)
getCipherByName name
    = withCString name $ \ namePtr ->
      do ptr <- _get_cipherbyname namePtr
         if ptr == nullPtr then
             return Nothing
           else
             return $ Just ptr
