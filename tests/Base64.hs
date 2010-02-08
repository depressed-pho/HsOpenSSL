{-# LANGUAGE OverloadedStrings  #-}

-- | Unittest for Base64 [en|de]coding.
module Main where

import           Data.Char (ord)
import           Data.String
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import           OpenSSL.EVP.Base64

{-
  Comment by PHO:

  These instance declarations now seem to be part of
  Data.ByteString. What should we do then?

  Base64.hs:12:9:
      Duplicate instance declarations:
        instance IsString BS.ByteString -- Defined at Base64.hs:12:9-30
        instance IsString BS.ByteString -- Defined in Data.ByteString.Char8

  Base64.hs:17:9:
      Duplicate instance declarations:
        instance IsString BSL.ByteString -- Defined at Base64.hs:17:9-31
        instance IsString BSL.ByteString
          -- Defined in Data.ByteString.Lazy.Char8
-}
{-
instance IsString BS.ByteString where
  fromString = BS.pack . map (fromIntegral . ord)

-- Note that this instance packs each charactor as a separate lazy chunk.
-- This is to stress the lazy code - not because it's a good idea generally
instance IsString BSL.ByteString where
  fromString = BSL.fromChunks . map (BS.singleton . fromIntegral . ord)
-}

encodeTests :: [(BS.ByteString, BS.ByteString)]
encodeTests =
  [("", "")
  ,("a", "YQ==")
  ,("aa", "YWE=")
  ,("aaa", "YWFh")
  ]

lazyEncodeTests :: [(BSL.ByteString, BSL.ByteString)]
lazyEncodeTests =
  [("", "")
  ,("a", "YQ==")
  ,("aa", "YWE=")
  ,("aaa", "YWFh")
  ]

decodeTests :: [(BS.ByteString, BS.ByteString)]
decodeTests =
  [("", "")
  ,("aGFza2VsbA==", "haskell")
  ,("YWJjZGVmZ2hpams=", "abcdefghijk")
  ,("YWJjZGVmZ2hpams=\n", "abcdefghijk")
  ]

encoding = all id $ map (\(a, v) -> encodeBase64BS a == v) encodeTests
lazyEncoding = all id $ map (\(a, v) -> encodeBase64LBS a == v) lazyEncodeTests
decoding = all id $ map (\(a, v) -> decodeBase64BS a == v) decodeTests

main = do
  mapM_ (print . encodeBase64LBS . fst) lazyEncodeTests
  if encoding && lazyEncoding && decoding
     then putStrLn "PASS"
     else putStrLn "FAIL"
