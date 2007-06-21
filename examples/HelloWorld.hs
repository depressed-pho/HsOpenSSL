import Control.Monad hiding (join)
import Data.List
import Data.Maybe
import Data.Time.Clock
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
       do x509 <- newX509
          setVersion x509 2
          setSerialNumber x509 12345678
          setIssuerName x509 [("C", "JP")]
          setSubjectName x509 [("ST", "foo")]
          setNotBefore x509 =<< getCurrentTime
          setNotAfter x509 =<< liftM (addUTCTime (365 * 24 * 60 * 60)) getCurrentTime

          cliPKey <- generateKey 512 65537 Nothing >>= newPKeyRSA
          setPublicKey x509 cliPKey

          caPem  <- readFile "../tmp/priv.pem"
          caPKey <- readPrivateKey caPem PwNone
          signX509 x509 caPKey Nothing

          setIssuerName x509 []
          verifyX509 x509 caPKey >>= print
{-
       do x509 <- readX509 =<< readFile "../tmp/cert.pem"
          getVersion      x509      >>= print
          getSerialNumber x509      >>= print
          getIssuerName   x509 True >>= print
          getSubjectName  x509 True >>= print
          getNotBefore    x509      >>= print
          getNotAfter     x509      >>= print
          getSubjectEmail x509      >>= print
-}
          
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
