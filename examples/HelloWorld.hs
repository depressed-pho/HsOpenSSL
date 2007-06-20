import Control.Monad hiding (join)
import Data.List
import Data.Maybe
import OpenSSL
import OpenSSL.BN
import OpenSSL.BIO as BIO
import OpenSSL.EVP.Base64
import OpenSSL.EVP.Cipher
import OpenSSL.EVP.Digest
import OpenSSL.EVP.Open
import OpenSSL.EVP.PKey
import OpenSSL.EVP.Seal
import OpenSSL.EVP.Sign
import OpenSSL.EVP.Verify
import OpenSSL.PEM
import OpenSSL.RSA
import OpenSSL.X509
import System.IO
import Text.Printf


main = withOpenSSL $
       do x509 <- readX509 =<< readFile "/usr/share/curl/curl-ca-bundle.crt" -- "../tmp/cert.pem"
          getVersion      x509      >>= print
          getSerialNumber x509      >>= print
          getIssuerName   x509 True >>= print
          getSubjectName  x509 True >>= print
          getNotBefore    x509      >>= print
          getNotAfter     x509      >>= print
          getEmail        x509      >>= print
          
{-
       do putStrLn "cipher: DES-CBC"
          des <- liftM fromJust $ getCipherByName "DES-CBC"

          putStrLn "generating RSA keypair..."
          pkey <- generateKey 512 65537 Nothing >>= newPKeyRSA

          let plainText = "Hello, world!"
          putStrLn ("plain text to encrypt: " ++ plainText)

          putStrLn ""

          putStrLn "encrypting..."
          (encrypted, [encKey], iv) <- seal des [pkey] plainText
          
          putStrLn ("encrypted symmetric key: " ++ binToHex encKey)
          putStrLn ("IV: " ++ binToHex iv)
          putStrLn ("encrypted message: " ++ binToHex encrypted)

          putStrLn ""

          putStrLn "decrypting..."
          decrypted <- open des encKey iv pkey encrypted

          putStrLn ("decrypted message: " ++ decrypted)
-}


binToHex :: String -> String
binToHex bin = concat $ intersperse ":" $ map (printf "%02x" . fromEnum) bin
