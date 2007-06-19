{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.EVP.Base64
    ( encodeBase64
    , encodeBase64BS
    , encodeBase64LBS

    , decodeBase64
    , decodeBase64BS
    , decodeBase64LBS
    )
    where

import           Control.Exception
import qualified Data.ByteString as B
import           Data.ByteString.Base
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Data.List
import           Foreign
import           Foreign.C
import           OpenSSL.Utils


-- エンコード時: 最低 3 バイト以上になるまで次のブロックを取り出し續け
-- る。返された[ByteString] は B.concat してから、その文字列長より小さ
-- な最大の 3 の倍數の位置で分割し、殘りは次のブロックの一部と見做す。
--
-- デコード時: 分割のアルゴリズムは同じだが最低バイト数が 4。
nextBlock :: Int -> ([ByteString], LazyByteString) -> ([ByteString], LazyByteString)
nextBlock _      (xs, LPS [] ) = (xs, LPS [])
nextBlock minLen (xs, LPS src) = if foldl' (+) 0 (map B.length xs) >= minLen then
                                     (xs, LPS src)
                                 else
                                     case src of
                                       (y:ys) -> nextBlock minLen (xs ++ [y], LPS ys)


{- encode -------------------------------------------------------------------- -}

foreign import ccall unsafe "EVP_EncodeBlock"
        _EncodeBlock :: Ptr CChar -> Ptr CChar -> Int -> IO Int


encodeBlock :: ByteString -> ByteString
encodeBlock inBS
    = unsafePerformIO $
      unsafeUseAsCStringLen inBS $ \ (inBuf, inLen) ->
      createAndTrim maxOutLen $ \ outBuf ->
      _EncodeBlock (unsafeCoercePtr outBuf) inBuf inLen
    where
      maxOutLen = (inputLen `div` 3 + 1) * 4 + 1 -- +1: '\0'
      inputLen  = B.length inBS


encodeBase64 :: String -> String
encodeBase64 = L8.unpack . encodeBase64LBS . L8.pack


encodeBase64BS :: ByteString -> ByteString
encodeBase64BS = encodeBlock


encodeBase64LBS :: LazyByteString -> LazyByteString
encodeBase64LBS inLBS
    | L8.null inLBS = L8.empty
    | otherwise
        = let (blockParts', remain' ) = nextBlock 3 ([], inLBS)
              block'                  = B.concat blockParts'
              blockLen'               = B.length block'
              (block      , leftover) = if blockLen' < 3 then
                                            -- 最後の半端
                                            (block', B.empty)
                                        else
                                            B.splitAt (blockLen' - blockLen' `mod` 3) block'
              remain                  = if B.null leftover then
                                            remain'
                                        else
                                            case remain' of
                                              LPS xs -> LPS (leftover:xs)
              encodedBlock             = encodeBlock block
              LPS encodedRemain        = encodeBase64LBS remain
          in
            LPS ([encodedBlock] ++ encodedRemain)


{- decode -------------------------------------------------------------------- -}

foreign import ccall unsafe "EVP_DecodeBlock"
        _DecodeBlock :: Ptr CChar -> Ptr CChar -> Int -> IO Int


decodeBlock :: ByteString -> ByteString
decodeBlock inBS
    = assert (B.length inBS `mod` 4 == 0) $
      unsafePerformIO $
      unsafeUseAsCStringLen inBS $ \ (inBuf, inLen) ->
      createAndTrim (B.length inBS) $ \ outBuf ->
      _DecodeBlock (unsafeCoercePtr outBuf) inBuf inLen


decodeBase64 :: String -> String
decodeBase64 = L8.unpack . decodeBase64LBS . L8.pack


decodeBase64BS :: ByteString -> ByteString
decodeBase64BS = decodeBlock


decodeBase64LBS :: LazyByteString -> LazyByteString
decodeBase64LBS inLBS
    | L8.null inLBS = L8.empty
    | otherwise
        = let (blockParts', remain' ) = nextBlock 4 ([], inLBS)
              block'                  = B.concat blockParts'
              blockLen'               = B.length block'
              (block      , leftover) = assert (blockLen' >= 4) $
                                        B.splitAt (blockLen' - blockLen' `mod` 4) block'
              remain                  = if B.null leftover then
                                            remain'
                                        else
                                            case remain' of
                                              LPS xs -> LPS (leftover:xs)
              decodedBlock            = decodeBlock block
              LPS decodedRemain       = decodeBase64LBS remain
          in
            LPS ([decodedBlock] ++ decodedRemain)
