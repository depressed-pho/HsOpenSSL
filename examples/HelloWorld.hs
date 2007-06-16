import Control.Monad hiding (join)
import Data.Maybe
import OpenSSL
import OpenSSL.BN
import OpenSSL.BIO as BIO
import OpenSSL.EVP.Cipher
import OpenSSL.EVP.Digest
import OpenSSL.EVP.Sign
import OpenSSL.EVP.Verify
import OpenSSL.PEM
import OpenSSL.RSA
import System.IO
import Text.Printf

main = withOpenSSL $
       do des <- liftM fromJust $ getCipherByName "DES-CBC"

          cipher <- newCipher des "hello" "" Decrypt
          mem    <- newMemBuf
          mem <== cipher

          encrypted <- readFile "/tmp/enc"
          BIO.write cipher encrypted
          BIO.flush cipher

          BIO.read mem >>= putStrLn
{-
          ctx <- encryptInit des "hello" ""
          encryptUpdate ctx "Hello, " >>= putStr
          encryptUpdate ctx "world!"  >>= putStr
          encryptFinal  ctx           >>= putStr
-}