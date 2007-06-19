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
import System.IO
import Text.Printf


main = withOpenSSL $
       do putStrLn "cipher: DES-CBC"
          des <- liftM fromJust $ getCipherByName "DES-CBC"

          putStrLn "generating RSA keypair..."
          pkey <- generateKey 512 65537 Nothing >>= newPKeyRSA

          let plainText = "Hello, world!"
          putStrLn ("plain text to encrypt: " ++ plainText)

          putStrLn ""

          putStrLn "encrypting..."
          (sealCtx, [encKey], iv) <- sealInit des [pkey]
          encrypted <- liftM concat $ sequence [ sealUpdate sealCtx plainText
                                               , sealFinal  sealCtx
                                               ]
          
          putStrLn ("encrypted symmetric key: " ++ binToHex encKey)
          putStrLn ("IV: " ++ binToHex iv)
          putStrLn ("encrypted message: " ++ binToHex encrypted)

          putStrLn ""

          putStrLn "decrypting..."
          openCtx <- openInit des encKey iv pkey
          decrypted <- liftM concat $ sequence [ openUpdate openCtx encrypted
                                               , openFinal  openCtx
                                               ]

          putStrLn ("decrypted message: " ++ decrypted)


binToHex :: String -> String
binToHex bin = concat $ intersperse ":" $ map (printf "%02x" . fromEnum) bin
