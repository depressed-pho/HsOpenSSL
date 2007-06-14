import Control.Monad hiding (join)
import OpenSSL
import OpenSSL.BN  as BN
import OpenSSL.BIO as BIO
import OpenSSL.EVP as EVP
import OpenSSL.RSA as RSA
import Text.Printf

main = withOpenSSL $
       do rsa <- generateKey 1024 65537 Nothing
          n    <- rsaN rsa
          e    <- rsaE rsa
          d    <- rsaD rsa
          p    <- rsaP rsa
          q    <- rsaQ rsa
          dmp1 <- rsaDMP1 rsa
          dmq1 <- rsaDMQ1 rsa
          iqmp <- rsaIQMP rsa
          
          printf "n (public modulus) = %s\n" (show n)
          printf "e (public exponent) = %s\n" (show e)
          printf "d (private exponent) = %s\n" (show d)
          printf "p (secret prime factor) = %s\n" (show p)
          printf "q (secret prime factor) = %s\n" (show q)
          printf "dmp1 (d mod (p-1)) = %s\n" (show dmp1)
          printf "dmq1 (d mod (q-1)) = %s\n" (show dmq1)
          printf "iqmp (q^-1 mod p) = %s\n" (show iqmp)
{-
       do base64 <- newBase64 True
          mem    <- newMemBuf

          base64 ==> mem

          write base64 "Hello, world!"
          flush base64
          result <- BIO.read mem

          putStrLn result
-}