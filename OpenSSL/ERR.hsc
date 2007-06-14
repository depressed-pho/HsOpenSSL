{- -*- haskell -*- -}
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
getError = _get_error >>= return . fromIntegral


peekError :: IO Integer
peekError = _peek_error >>= return . fromIntegral


errorString :: Integer -> IO String
errorString code
    = _error_string (fromIntegral code) nullPtr >>= peekCString
