module OpenSSL.ERR
    ( getError
    , peekError

    , errorString
    )
    where

import           Foreign
import           Foreign.C


foreign import ccall unsafe "ERR_get_error"
        _get_error :: IO CULong

foreign import ccall unsafe "ERR_peek_error"
        _peek_error :: IO CULong

foreign import ccall unsafe "ERR_error_string"
        _error_string :: CULong -> CString -> IO CString


getError :: IO Integer
getError = fmap fromIntegral _get_error


peekError :: IO Integer
peekError = fmap fromIntegral _peek_error


errorString :: Integer -> IO String
errorString code
    = _error_string (fromIntegral code) nullPtr >>= peekCString
