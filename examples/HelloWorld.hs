import Control.Monad hiding (join)
import Data.Maybe
import OpenSSL
import OpenSSL.BN
import OpenSSL.BIO
import OpenSSL.EVP
import OpenSSL.EVP.Digest
import OpenSSL.EVP.Sign
import OpenSSL.PEM
import OpenSSL.RSA
import System.IO
import Text.Printf

main = withOpenSSL $
       do sha1 <- liftM fromJust $ getDigestByName "SHA1"
          pem  <- readFile "/tmp/pkey.pem"
          pkey <- readPrivateKeyFromString pem PwNone
          ctx  <- initSign sha1
          updateSign ctx "Hello, "
          updateSign ctx "World!"
          finalizeSign ctx pkey >>= putStr
