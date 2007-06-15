{- -*- haskell -*- -}
module OpenSSL.EVP
    ( EvpMD
    , EVP_MD
    , getDigestByName
    , mdSize

    , EvpCipher
    , EVP_CIPHER
    , getCipherByName

    , EvpPKey
    , EVP_PKEY
      -- FIXME: newPKeyDSA, newPKeyDH and newPKeyECKey may be needed
#ifndef OPENSSL_NO_RSA
    , newPKeyRSA
#endif
    )
    where

#include "HsOpenSSL.h"

import           Foreign
import           Foreign.C
import           OpenSSL.RSA
import           OpenSSL.Utils

{- digest -------------------------------------------------------------------- -}

type EvpMD  = Ptr EVP_MD
data EVP_MD = EVP_MD


foreign import ccall unsafe "EVP_get_digestbyname"
        _get_digestbyname :: CString -> IO EvpMD

foreign import ccall unsafe "HsOpenSSL_EVP_MD_size"
        mdSize :: EvpMD -> Int


getDigestByName :: String -> IO (Maybe EvpMD)
getDigestByName name
    = withCString name $ \ namePtr ->
      do ptr <- _get_digestbyname namePtr
         if ptr == nullPtr then
             return Nothing
           else
             return $ Just ptr


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


{- EVP_PKEY ------------------------------------------------------------------ -}

type EvpPKey  = ForeignPtr EVP_PKEY
data EVP_PKEY = EVP_PKEY


foreign import ccall unsafe "EVP_PKEY_new"
        _new :: IO (Ptr EVP_PKEY)

foreign import ccall unsafe "&EVP_PKEY_free"
        _free :: FunPtr (Ptr EVP_PKEY -> IO ())


#ifndef OPENSSL_NO_RSA
foreign import ccall unsafe "EVP_PKEY_set1_RSA"
        _set1_RSA :: Ptr EVP_PKEY -> Ptr RSA_ -> IO Int

-- set1_RSA は RSA* の參照カウントを上げるので、
-- [1] EvpPKey が先に破棄された場合、RSA* の所有者が RSA だけになる。
-- [2] RSA が先に破棄された場合、RSA* の所有者が EvpPKey だけになる。
-- よって EvpPKey が敢えて RSA への參照を作らなくても問題無い。（作って
-- も問題無いが）
       
newPKeyRSA :: RSA -> IO EvpPKey
newPKeyRSA rsa
    = withForeignPtr rsa $ \ rsaPtr ->
      do pkey <- _new >>= failIfNull
         _set1_RSA pkey rsaPtr >>= failIf (/= 1)
         newForeignPtr _free pkey
#endif
