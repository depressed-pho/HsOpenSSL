{- -*- haskell -*- -}
module OpenSSL.EVP
    ( EvpMD(..)

    , md_null
    , md_md2
    , md_md5
    , md_sha
    , md_sha1
    , md_dss
    , md_dss1
    , md_mdc2
    , md_ripemd160
    , getDigestByName

    , mdSize
    )
    where

#include "HsOpenSSL.h"

import           Foreign
import           Foreign.C
import           OpenSSL.Utils

{- MD ------------------------------------------------------------------------ -}

newtype EvpMD     = EvpMD (Ptr ())
type    EvpMD_ptr = Ptr ()

foreign import ccall "EVP_get_digestbyname"
        _get_digestbyname :: CString -> IO EvpMD_ptr

foreign import ccall "EVP_md_null"
        _md_null :: IO EvpMD_ptr

foreign import ccall "EVP_md2"
        _md_md2 :: IO EvpMD_ptr

foreign import ccall "EVP_md5"
        _md_md5 :: IO EvpMD_ptr

foreign import ccall "EVP_sha"
        _md_sha :: IO EvpMD_ptr

foreign import ccall "EVP_sha1"
        _md_sha1 :: IO EvpMD_ptr

foreign import ccall "EVP_dss"
        _md_dss :: IO EvpMD_ptr

foreign import ccall "EVP_dss1"
        _md_dss1 :: IO EvpMD_ptr

foreign import ccall "EVP_mdc2"
        _md_mdc2 :: IO EvpMD_ptr

foreign import ccall "EVP_ripemd160"
        _md_ripemd160 :: IO EvpMD_ptr

foreign import ccall "HsOpenSSL_EVP_MD_size"
        _md_size :: EvpMD_ptr -> Int


md_null :: IO EvpMD
md_null = _md_null >>= failIfNull >>= return . EvpMD

md_md2 :: IO EvpMD
md_md2 = _md_md2 >>= failIfNull >>= return . EvpMD

md_md5 :: IO EvpMD
md_md5 = _md_md5 >>= failIfNull >>= return . EvpMD

md_sha :: IO EvpMD
md_sha = _md_sha >>= failIfNull >>= return . EvpMD

md_sha1 :: IO EvpMD
md_sha1 = _md_sha1 >>= failIfNull >>= return . EvpMD

md_dss :: IO EvpMD
md_dss = _md_dss >>= failIfNull >>= return . EvpMD

md_dss1 :: IO EvpMD
md_dss1 = _md_dss1 >>= failIfNull >>= return . EvpMD

md_mdc2 :: IO EvpMD
md_mdc2 = _md_mdc2 >>= failIfNull >>= return . EvpMD

md_ripemd160 :: IO EvpMD
md_ripemd160 = _md_ripemd160 >>= failIfNull >>= return . EvpMD


getDigestByName :: String -> IO (Maybe EvpMD)
getDigestByName name
    = withCString name $ \ namePtr ->
      do ptr <- _get_digestbyname namePtr
         if ptr == nullPtr then
             return Nothing
           else
             return $ Just $ EvpMD ptr


mdSize :: EvpMD -> Int
mdSize (EvpMD md)
    = _md_size md