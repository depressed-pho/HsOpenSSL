module Main where

import Control.Concurrent (threadDelay)
import Network.Socket
import OpenSSL
import qualified OpenSSL.Session as SSL

main = withOpenSSL main'

main' = do
  sock <- socket AF_INET Stream 0
  bindSocket sock $ SockAddrInet (fromIntegral 4112) iNADDR_ANY
  setSocketOption sock ReuseAddr 1
  listen sock 1
  (sock', sockaddr) <- accept sock
  print $ "Accepted connection from " ++ show sockaddr

  ctx <- SSL.context
  SSL.contextSetPrivateKeyFile ctx "server.pem"
  SSL.contextSetCertificateFile ctx "server.crt"
  SSL.contextSetCiphers ctx "DEFAULT"
  SSL.contextCheckPrivateKey ctx >>= print
  conn <- SSL.connection ctx sock'
  SSL.accept conn
  b <- SSL.read conn 1024
  SSL.write conn b
  SSL.shutdown conn SSL.Bidirectional

