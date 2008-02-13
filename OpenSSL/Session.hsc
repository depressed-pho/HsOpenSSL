{-# OPTIONS_GHC -fno-warn-name-shadowing #-}
-- | Functions for handling SSL/TLS connections over Sockets. The Sockets are
--   wrapped in BIO objects so that openssl works well with Haskell's threading
--   system (i.e. a 'blocking' read will actually allow other green threads to
--   run rather than blocking the whole OS thread)
module OpenSSL.Session
  ( -- * Contexts
    SSLContext
  , context
  , contextSetPrivateKeyFile
  , contextSetCertificateFile
  , contextSetCiphers
  , contextSetDefaultCiphers
  , contextCheckPrivateKey

    -- * SSL connections
  , SSL
  , connection
  , accept
  , read
  , write
  , ShutdownType(..)
  , shutdown
  ) where

#include "openssl/ssl.h"

import Prelude hiding (read)
import Foreign
import Foreign.C
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe as B
import Network.Socket (Socket)

import OpenSSL.Utils (failIfNull, failIf, raiseOpenSSLError)
import OpenSSL.BIO (BIO, BIO_, withBioPtr)
import OpenSSL.SocketBIO (socketToBIO)

data SSLContext_
-- | An SSL context. Contexts carry configuration such as a server's private
--   key, root CA certiifcates etc. Contexts are stateful IO objects; they
--   start empty and various options are set on them by the functions in this
--   module. Note that an empty context will pretty much cause any operation to
--   fail since it doesn't even have any ciphers enabled.
newtype SSLContext = SSLContext (ForeignPtr SSLContext_)

data SSLMethod_

foreign import ccall unsafe "SSL_CTX_new" _ssl_ctx_new :: Ptr SSLMethod_ -> IO (Ptr SSLContext_)
foreign import ccall unsafe "&SSL_CTX_free" _ssl_ctx_free :: FunPtr (Ptr SSLContext_ -> IO ())
foreign import ccall unsafe "SSLv23_method" _ssl_method :: IO (Ptr SSLMethod_)

-- | Create a new SSL context.
context :: IO SSLContext
context = _ssl_method >>= _ssl_ctx_new >>= newForeignPtr _ssl_ctx_free >>= return . SSLContext

contextLoadFile :: (Ptr SSLContext_ -> CString -> CInt -> IO Int)
                -> SSLContext -> String -> IO ()
contextLoadFile f (SSLContext context) path =
  withForeignPtr context $ \ctx ->
    withCString path $ \cpath -> do
      result <- f ctx cpath (#const SSL_FILETYPE_PEM)
      if result == 1
         then return ()
         else f ctx cpath (#const SSL_FILETYPE_ASN1) >>= failIf (/= 1) >> return ()

foreign import ccall unsafe "SSL_CTX_use_PrivateKey_file"
   _ssl_ctx_use_privatekey_file :: Ptr SSLContext_ -> CString -> CInt -> IO Int
foreign import ccall unsafe "SSL_CTX_use_certificate_file"
   _ssl_ctx_use_certificate_file :: Ptr SSLContext_ -> CString -> CInt -> IO Int

-- | Install a private key file in a context. The key is given as a path to the
--   file which contains the key. The file is parsed first as PEM and, if that
--   fails, as ASN1. If both fail, an exception is raised.
contextSetPrivateKeyFile :: SSLContext -> FilePath -> IO ()
contextSetPrivateKeyFile = contextLoadFile _ssl_ctx_use_privatekey_file

-- | Install a certificate (public key) file in a context. The key is given as
--   a path to the file which contains the key. The file is parsed first as PEM
--   and, if that fails, as ASN1. If both fail, an exception is raised.
contextSetCertificateFile :: SSLContext -> FilePath -> IO ()
contextSetCertificateFile = contextLoadFile _ssl_ctx_use_certificate_file

foreign import ccall unsafe "SSL_CTX_set_cipher_list"
   _ssl_ctx_set_cipher_list :: Ptr SSLContext_ -> CString -> IO Int

-- | Set the ciphers to be used by the given context. The string argument is a
--   list of ciphers, comma separated, as given at
--   http://www.openssl.org/docs/apps/ciphers.html
--
--   Unrecognised ciphers are ignored. If no ciphers from the list are
--   recognised, an exception is raised.
contextSetCiphers :: SSLContext -> String -> IO ()
contextSetCiphers (SSLContext context) list =
  withForeignPtr context $ \ctx ->
    withCString list $ \cpath ->
      _ssl_ctx_set_cipher_list ctx cpath >>= failIf (/= 1) >> return ()

contextSetDefaultCiphers :: SSLContext -> IO ()
contextSetDefaultCiphers = flip contextSetCiphers "DEFAULT"

foreign import ccall unsafe "SSL_CTX_check_private_key"
   _ssl_ctx_check_private_key :: Ptr SSLContext_ -> IO Int

-- | Return true iff the private key installed in the given context matches the
--   certificate also installed.
contextCheckPrivateKey :: SSLContext -> IO Bool
contextCheckPrivateKey (SSLContext context) =
  withForeignPtr context $ \ctx ->
    _ssl_ctx_check_private_key ctx >>= return . (==) 1

data SSL_
-- | This is the type of an SSL connection
newtype SSL = SSL (Socket, BIO, ForeignPtr SSL_)

foreign import ccall unsafe "SSL_new" _ssl_new :: Ptr SSLContext_ -> IO (Ptr SSL_)
foreign import ccall unsafe "&SSL_free" _ssl_free :: FunPtr (Ptr SSL_ -> IO ())
foreign import ccall unsafe "SSL_set_bio" _ssl_set_bio :: Ptr SSL_ -> Ptr BIO_ -> Ptr BIO_ -> IO ()

-- | Wrap a Socket in an SSL connection. Reading and writing to the Socket
--   after this will cause weird errors in the SSL code. The SSL object
--   carries a handle to the Socket so you need not worry about the garbage
--   collector closing the file descriptor out from under you.
connection :: SSLContext -> Socket -> IO SSL
connection (SSLContext context) sock = do
  bio <- socketToBIO sock
  ssl <- withBioPtr bio (\bio -> do
    withForeignPtr context (\ctx -> do
      ssl <- _ssl_new ctx >>= failIfNull
      _ssl_set_bio ssl bio bio
      return ssl))
  fpssl <- newForeignPtr _ssl_free ssl
  return $ SSL (sock, bio, fpssl)

foreign import ccall "SSL_accept" _ssl_accept :: Ptr SSL_ -> IO CInt

-- | Perform an SSL server handshake
accept :: SSL -> IO ()
accept (SSL (_, _, ssl)) = withForeignPtr ssl (\ssl -> do
  _ssl_accept ssl >>= failIf (/= 1)) >> return ()

foreign import ccall "SSL_read" _ssl_read :: Ptr SSL_ -> Ptr Word8 -> CInt -> IO CInt
foreign import ccall unsafe "SSL_get_shutdown" _ssl_get_shutdown :: Ptr SSL_ -> IO CInt

-- | Try the read the given number of bytes from an SSL connection. On EOF an
--   empty ByteString is returned. If the connection dies without a graceful
--   SSL shutdown, an exception is raised.
read :: SSL -> Int -> IO B.ByteString
read (SSL (_, _, ssl)) nbytes = B.createAndTrim nbytes $ \ptr ->
  withForeignPtr ssl $ \ssl -> do
    n <- _ssl_read ssl ptr $ fromIntegral nbytes
    if n > 0
       then return $ fromIntegral n
       else if n < 0
            then raiseOpenSSLError
            else do
              shutdown <- _ssl_get_shutdown ssl
              if shutdown .&. (#const SSL_RECEIVED_SHUTDOWN) /= 0
                 then return 0
                 else fail "SSL connection abruptly terminated"

foreign import ccall "SSL_write" _ssl_write :: Ptr SSL_ -> Ptr CChar -> CInt -> IO CInt

-- | Write a given ByteString to the SSL connection. Either all the data is
--   written or an exception is raised because of an error
write :: SSL -> B.ByteString -> IO ()
write (SSL (_, _, ssl)) bs = do
  withForeignPtr ssl $ \ssl ->
    B.unsafeUseAsCStringLen bs $ \(ptr, nbytes) ->
      let f _ 0 = return ()
          f ptr nbytes = do
            n <- _ssl_write ssl ptr (fromIntegral nbytes) >>= return . fromIntegral
            if n <= 0
               then raiseOpenSSLError
               else f (ptr `plusPtr` n) (nbytes - n)
      in f ptr nbytes

foreign import ccall "SSL_shutdown" _ssl_shutdown :: Ptr SSL_ -> IO CInt

data ShutdownType = Bidirectional  -- ^ wait for the peer to also shutdown
                  | Unidirectional  -- ^ only send our shutdown

-- | Cleanly shutdown an SSL connection. Note that SSL has a concept of a
--   secure shutdown, which is distinct from just closing the TCP connection.
--   This performs the former and should always be preferred.
--
--   This can either just send a shutdown, or can send and wait for the peer's
--   shutdown message.
shutdown :: SSL -> ShutdownType -> IO ()
shutdown (SSL (_, _, ssl)) ty =
  withForeignPtr ssl $ \ssl -> do
    n <- _ssl_shutdown ssl >>= failIf (< 0)
    case ty of
         Unidirectional -> return ()
         Bidirectional -> do
           if n == 1
              then return ()
              else _ssl_shutdown ssl >>= failIf (< 0) >> return ()
