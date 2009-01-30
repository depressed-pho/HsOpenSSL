module OpenSSL.Utils
    ( failIfNull
    , failIf
    , raiseOpenSSLError
    , toHex
    , fromHex
    , peekCStringCLen
    )
    where

import           Foreign
import           Foreign.C
import           OpenSSL.ERR
import           Data.Bits ((.&.), (.|.), shiftR, shiftL)
import           Data.List (unfoldr)

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

-- | Convert an integer to a hex string
toHex :: (Bits i) => i -> String
toHex = reverse . map hexByte . unfoldr step where
  step 0 = Nothing
  step i = Just (i .&. 0xf, i `shiftR` 4)

  hexByte 0 = '0'
  hexByte 1 = '1'
  hexByte 2 = '2'
  hexByte 3 = '3'
  hexByte 4 = '4'
  hexByte 5 = '5'
  hexByte 6 = '6'
  hexByte 7 = '7'
  hexByte 8 = '8'
  hexByte 9 = '9'
  hexByte 10 = 'a'
  hexByte 11 = 'b'
  hexByte 12 = 'c'
  hexByte 13 = 'd'
  hexByte 14 = 'e'
  hexByte 15 = 'f'
  hexByte _  = undefined

-- | Convert a hex string to an integer
fromHex :: (Bits i) => String -> i
fromHex = foldl step 0 where
  step acc hexchar = (acc `shiftL` 4) .|. (byteHex hexchar)

  byteHex '0' = 0
  byteHex '1' = 1
  byteHex '2' = 2
  byteHex '3' = 3
  byteHex '4' = 4
  byteHex '5' = 5
  byteHex '6' = 6
  byteHex '7' = 7
  byteHex '8' = 8
  byteHex '9' = 9
  byteHex 'a' = 10
  byteHex 'b' = 11
  byteHex 'c' = 12
  byteHex 'd' = 13
  byteHex 'e' = 14
  byteHex 'f' = 15
  byteHex 'A' = 10
  byteHex 'B' = 11
  byteHex 'C' = 12
  byteHex 'D' = 13
  byteHex 'E' = 14
  byteHex 'F' = 15
  byteHex _   = undefined


peekCStringCLen :: (Ptr CChar, CInt) -> IO String
peekCStringCLen (p, n)
    = peekCStringLen (p, fromIntegral n)