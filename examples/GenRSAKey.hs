import Control.Monad hiding (join)
import OpenSSL
import OpenSSL.BN
import OpenSSL.BIO
import OpenSSL.EVP.PKey
import OpenSSL.PEM
import OpenSSL.RSA
import System.IO
import Text.Printf

main = withOpenSSL $
       do let keyBits = 512
              keyE    = 65537

          printf "Generating RSA key-pair, nbits = %d, e = %d:\n" keyBits keyE
          
          rsa  <- generateKey keyBits keyE $ Just $ \ phase _ ->
                  do hPutChar stdout $ case phase of
                                         0 -> '.'
                                         1 -> '+'
                                         2 -> '*'
                                         3 -> '\n'
                                         n -> head $ show n
                     hFlush stdout

          printf "Done.\n"
          
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

          pkey <- newPKeyRSA rsa
          writePKCS8PrivateKeyToString pkey Nothing >>= putStr
          -- writePublicKeyToString pkey >>= putStr
