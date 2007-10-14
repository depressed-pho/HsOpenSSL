module Main where

import System.Time

import OpenSSL.DSA
import qualified Data.ByteString as BS

-- | This function just runs the example DSA generation, as given in FIP 186-2,
--   app 5.
test_generateParameters = do
  let seed = BS.pack [0xd5, 0x01, 0x4e, 0x4b,
                      0x60, 0xef, 0x2b, 0xa8,
                      0xb6, 0x21, 0x1b, 0x40,
                      0x62, 0xba, 0x32, 0x24,
                      0xe0, 0x42, 0x7d, 0xd3]
  (a, b, p, q, g) <- generateParameters 512 $ Just seed
  return $ (a, p, q, g) == (105,
   0x8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291,
   0xc773218c737ec8ee993b4f2ded30f48edace915f,
   0x626d027839ea0a13413163a55b4cb500299d5522956cefcb3bff10f399ce2c2e71cb9de5fa24babf58e5b79521925c9cc42e9f6f464b088cc572af53e6d78802)

testMessage = BS.pack [1, 2, 3, 4,  5, 6, 7, 8,  9, 10, 11, 12,  13, 14, 15, 16,  17, 18, 19, 20]

test_signVerify = do
  dsa <- generateParametersAndKey 512 Nothing
  (a, b) <- signDigestedData dsa testMessage
  verifyDigestedData dsa testMessage (a, b)

test_signVerifySpeed = do
  dsa <- generateParametersAndKey 512 Nothing

  let test = do
        (a, b) <- signDigestedData dsa testMessage
        verifyDigestedData dsa testMessage (a, b)

  starttime <- getClockTime
  sequence_ $ take 2000 $ repeat test
  endtime <- getClockTime
  print $ diffClockTimes endtime starttime

  return True

main = do
  results <- sequence [test_generateParameters, test_signVerify, test_signVerifySpeed]
  if all id results
    then putStrLn "PASS"
    else putStrLn $ "FAIL" ++ show results
