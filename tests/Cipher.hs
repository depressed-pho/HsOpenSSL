-- | Tests for the non-EVP ciphers
module Main where

import           Control.Monad (when)
import qualified Data.ByteString as BS

import           OpenSSL.Cipher

-- | Convert a hex string to a ByteString (e.g. "0011" == BS.pack [0, 0x11])
hexToBS [] = BS.empty
hexToBS (a : b : rest) = BS.append (BS.singleton ((valueOfHexChar a * 16) + valueOfHexChar b))
                                         (hexToBS rest)

valueOfHexChar '0' = 0
valueOfHexChar '1' = 1
valueOfHexChar '2' = 2
valueOfHexChar '3' = 3
valueOfHexChar '4' = 4
valueOfHexChar '5' = 5
valueOfHexChar '6' = 6
valueOfHexChar '7' = 7
valueOfHexChar '8' = 8
valueOfHexChar '9' = 9
valueOfHexChar 'a' = 10
valueOfHexChar 'b' = 11
valueOfHexChar 'c' = 12
valueOfHexChar 'd' = 13
valueOfHexChar 'e' = 14
valueOfHexChar 'f' = 15
valueOfHexChar 'A' = 10
valueOfHexChar 'B' = 11
valueOfHexChar 'C' = 12
valueOfHexChar 'D' = 13
valueOfHexChar 'E' = 14
valueOfHexChar 'F' = 15

hexOf 0 = '0'
hexOf 1 = '1'
hexOf 2 = '2'
hexOf 3 = '3'
hexOf 4 = '4'
hexOf 5 = '5'
hexOf 6 = '6'
hexOf 7 = '7'
hexOf 8 = '8'
hexOf 9 = '9'
hexOf 10 = 'a'
hexOf 11 = 'b'
hexOf 12 = 'c'
hexOf 13 = 'd'
hexOf 14 = 'e'
hexOf 15 = 'f'

-- | A test containing counter mode test vectors
data CTRTest = CTRTest BS.ByteString  -- ^ key
                       BS.ByteString  -- ^ IV
                       BS.ByteString  -- ^ plaintext
                       BS.ByteString  -- ^ cipher text

-- Test vectors from draft-ietf-ipsec-ciph-aes-ctr-05 section 6
ctrTests = [
  CTRTest (hexToBS "AE6852F8121067CC4BF7A5765577F39E")
          (hexToBS "00000030000000000000000000000001")
          (hexToBS "53696E676C6520626C6F636B206D7367")
          (hexToBS "E4095D4FB7A7B3792D6175A3261311B8"),
  CTRTest (hexToBS "7691BE035E5020A8AC6E618529F9A0DC")
          (hexToBS "00E0017B27777F3F4A1786F000000001")
          (hexToBS "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223")
          (hexToBS "C1CF48A89F2FFDD9CF4652E9EFDB72D74540A42BDE6D7836D59A5CEAAEF3105325B2072F"),
  CTRTest (hexToBS "16AF5B145FC9F579C175F93E3BFB0EED863D06CCFDB78515")
          (hexToBS "0000004836733C147D6D93CB00000001")
          (hexToBS "53696E676C6520626C6F636B206D7367")
          (hexToBS "4B55384FE259C9C84E7935A003CBE928"),
  CTRTest (hexToBS "FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D")
          (hexToBS "001CC5B751A51D70A1C1114800000001")
          (hexToBS "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223")
          (hexToBS "EB6C52821D0BBBF7CE7594462ACA4FAAB407DF866569FD07F48CC0B583D6071F1EC0E6B8") ]

runCtrTest :: CTRTest -> IO Bool
runCtrTest (CTRTest key iv plaintext ciphertext) = do
  ctx <- newAESCtx Encrypt key iv
  ct <- aesCTR ctx plaintext
  return (ct == ciphertext)

runCtrTests :: IO Bool
runCtrTests = mapM runCtrTest ctrTests >>= return . all ((==) True)

main = do
  r <- runCtrTests
  when (r == False) $ fail "CTR tests failed"
  putStrLn "PASS"
