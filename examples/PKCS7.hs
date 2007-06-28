import Control.Monad
import Data.Time.Clock
import OpenSSL
import OpenSSL.PKCS7
import OpenSSL.EVP.PKey
import OpenSSL.PEM
import OpenSSL.RSA
import OpenSSL.X509

main = withOpenSSL $
       do pkey <- generateKey 512 65537 Nothing >>= newPKeyRSA
          x509 <- genCert pkey
          
          pkcs7 <- pkcs7Sign x509 pkey [] "Hello, world!" []
          writeSmime pkcs7 (Just "Hello, world!") [] >>= putStr

          return ()


genCert :: EvpPKey -> IO X509
genCert pkey
    = do x509 <- newX509
         setIssuerName  x509 [("C", "JP")]
         setSubjectName x509 [("C", "JP")]
         setNotBefore x509 =<< getCurrentTime
         setNotAfter  x509 =<< liftM (addUTCTime $ 365 * 24 * 60 * 60) getCurrentTime
         setPublicKey x509 pkey
         signX509 x509 pkey Nothing
         return x509
