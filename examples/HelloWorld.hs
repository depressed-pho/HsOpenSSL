import Control.Monad hiding (join)
import OpenSSL
import OpenSSL.BIO as BIO
import OpenSSL.EVP as EVP

main = withOpenSSL $
       do base64 <- newBase64 True
          mem    <- newMemBuf

          base64 ==> mem

          write base64 "Hello, world!"
          flush base64
          result <- BIO.read mem

          putStrLn result
