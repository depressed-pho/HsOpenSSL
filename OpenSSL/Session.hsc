{-# OPTIONS_GHC -fno-warn-name-shadowing #-}
-- | Functions for handling SSL connections. These functions use GHC specific
--   calls to cooperative the with the scheduler so that 'blocking' functions
--   only actually block the Haskell thread, not a whole OS thread.
module OpenSSL.Session
  ( -- * Contexts
    SSLContext
  , context
  , contextSetPrivateKeyFile
  , contextSetCertificateFile
  , contextSetCiphers
  , contextSetDefaultCiphers
  , contextCheckPrivateKey
  , VerificationMode(..)
  , contextSetVerificationMode
  , contextSetCAFile
  , contextSetCADirectory

    -- * SSL connections
  , SSL
  , connection
  , accept
  , connect
  , read
  , write
  , lazyRead
  , lazyWrite
  , shutdown
  , ShutdownType(..)
  , getPeerCertificate
  , getVerifyResult
  , sslSocket
  ) where

#include "openssl/ssl.h"

import Prelude hiding (read, ioError)
import Control.Concurrent (threadWaitWrite, threadWaitRead)
import Control.Concurrent.QSem
import Control.Exception (finally)
import Foreign
import Foreign.C
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.IO.Error (mkIOError, ioError, eofErrorType, catch, isEOFError)
import System.IO.Unsafe
import System.Posix.Types (Fd(..))
import Network.Socket (Socket(..))

import OpenSSL.Utils (failIfNull, failIf)
import OpenSSL.X509 (X509, X509_, wrapX509)

data SSLContext_
-- | An SSL context. Contexts carry configuration such as a server's private
--   key, root CA certiifcates etc. Contexts are stateful IO objects; they
--   start empty and various options are set on them by the functions in this
--   module. Note that an empty context will pretty much cause any operation to
--   fail since it doesn't even have any ciphers enabled.
--
--   Contexts are not thread safe so they carry a QSem with them which only
--   lets a single thread work inside them at a time. Thus, one must always use
--   withContext, not withForeignPtr directly.
newtype SSLContext = SSLContext (QSem, ForeignPtr SSLContext_)

data SSLMethod_

foreign import ccall unsafe "SSL_CTX_new" _ssl_ctx_new :: Ptr SSLMethod_ -> IO (Ptr SSLContext_)
foreign import ccall unsafe "&SSL_CTX_free" _ssl_ctx_free :: FunPtr (Ptr SSLContext_ -> IO ())
foreign import ccall unsafe "SSLv23_method" _ssl_method :: IO (Ptr SSLMethod_)

-- | Create a new SSL context.
context :: IO SSLContext
context = do
  ctx <- _ssl_method >>= _ssl_ctx_new
  context <- newForeignPtr _ssl_ctx_free ctx
  sem <- newQSem 1
  return $ SSLContext (sem, context)

-- | Run the given action with the raw context pointer and obtain the lock
--   while doing so.
withContext :: SSLContext -> (Ptr SSLContext_ -> IO a) -> IO a
withContext (SSLContext (sem, ctxfp)) action = do
  waitQSem sem
  finally (withForeignPtr ctxfp action) $ signalQSem sem

contextLoadFile :: (Ptr SSLContext_ -> CString -> CInt -> IO CInt)
                -> SSLContext -> String -> IO ()
contextLoadFile f context path =
  withContext context $ \ctx ->
    withCString path $ \cpath -> do
      result <- f ctx cpath (#const SSL_FILETYPE_PEM)
      if result == 1
         then return ()
         else f ctx cpath (#const SSL_FILETYPE_ASN1) >>= failIf (/= 1) >> return ()

foreign import ccall unsafe "SSL_CTX_use_PrivateKey_file"
   _ssl_ctx_use_privatekey_file :: Ptr SSLContext_ -> CString -> CInt -> IO CInt
foreign import ccall unsafe "SSL_CTX_use_certificate_file"
   _ssl_ctx_use_certificate_file :: Ptr SSLContext_ -> CString -> CInt -> IO CInt

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
   _ssl_ctx_set_cipher_list :: Ptr SSLContext_ -> CString -> IO CInt

-- | Set the ciphers to be used by the given context. The string argument is a
--   list of ciphers, comma separated, as given at
--   http://www.openssl.org/docs/apps/ciphers.html
--
--   Unrecognised ciphers are ignored. If no ciphers from the list are
--   recognised, an exception is raised.
contextSetCiphers :: SSLContext -> String -> IO ()
contextSetCiphers context list =
  withContext context $ \ctx ->
    withCString list $ \cpath ->
      _ssl_ctx_set_cipher_list ctx cpath >>= failIf (/= 1) >> return ()

contextSetDefaultCiphers :: SSLContext -> IO ()
contextSetDefaultCiphers = flip contextSetCiphers "DEFAULT"

foreign import ccall unsafe "SSL_CTX_check_private_key"
   _ssl_ctx_check_private_key :: Ptr SSLContext_ -> IO CInt

-- | Return true iff the private key installed in the given context matches the
--   certificate also installed.
contextCheckPrivateKey :: SSLContext -> IO Bool
contextCheckPrivateKey context =
  withContext context $ \ctx ->
    _ssl_ctx_check_private_key ctx >>= return . (==) 1

-- | See <http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html>
data VerificationMode = VerifyNone
                      | VerifyPeer {
                          vpFailIfNoPeerCert :: Bool  -- ^ is a certificate required
                        , vpClientOnce       :: Bool  -- ^ only request once per connection
                        }

foreign import ccall unsafe "SSL_CTX_set_verify"
   _ssl_set_verify_mode :: Ptr SSLContext_ -> CInt -> Ptr () -> IO ()

contextSetVerificationMode :: SSLContext -> VerificationMode -> IO ()
contextSetVerificationMode context VerifyNone = do
  withContext context $ \ctx ->
    _ssl_set_verify_mode ctx (#const SSL_VERIFY_NONE) nullPtr >> return ()

contextSetVerificationMode context (VerifyPeer reqp oncep) = do
  let mode = (#const SSL_VERIFY_PEER) .|.
             (if reqp then (#const SSL_VERIFY_FAIL_IF_NO_PEER_CERT) else 0) .|.
             (if oncep then (#const SSL_VERIFY_CLIENT_ONCE) else 0)
  withContext context $ \ctx ->
    _ssl_set_verify_mode ctx mode nullPtr >> return ()

foreign import ccall unsafe "SSL_CTX_load_verify_locations"
  _ssl_load_verify_locations :: Ptr SSLContext_ -> Ptr CChar -> Ptr CChar -> IO CInt

-- | Set the location of a PEM encoded list of CA certificates to be used when
--   verifying a server's certificate
contextSetCAFile :: SSLContext -> FilePath -> IO ()
contextSetCAFile context path = do
  withContext context $ \ctx ->
    withCString path $ \cpath -> do
      _ssl_load_verify_locations ctx cpath nullPtr >>= failIf (/= 1)
      return ()

-- | Set the path to a directory which contains the PEM encoded CA root
--   certificates. This is an alternative to 'contextSetCAFile'. See
--   <http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html> for
--   details of the file naming scheme
contextSetCADirectory :: SSLContext -> FilePath -> IO ()
contextSetCADirectory context path = do
  withContext context $ \ctx ->
    withCString path $ \cpath -> do
      _ssl_load_verify_locations ctx nullPtr cpath >>= failIf (/= 1)
      return ()



data SSL_
-- | This is the type of an SSL connection
--
--   SSL objects are not thread safe, so they carry a QSem around with them
--   which only lets a single thread work inside them at a time. Thus, one must
--   always use withSSL, rather than withForeignPtr directly.
--
--   IO with SSL objects is non-blocking and many SSL functions return a error
--   code which signifies that it needs to read or write more data. We handle
--   these calls and call threadWaitRead and threadWaitWrite at the correct
--   times. Thus multiple OS threads can be 'blocked' inside IO in the same SSL
--   object at a time, because they aren't really in the SSL object, they are
--   waiting for the RTS to wake the Haskell thread.
newtype SSL = SSL (QSem, ForeignPtr SSL_, Fd, Socket)

foreign import ccall unsafe "SSL_new" _ssl_new :: Ptr SSLContext_ -> IO (Ptr SSL_)
foreign import ccall unsafe "&SSL_free" _ssl_free :: FunPtr (Ptr SSL_ -> IO ())
foreign import ccall unsafe "SSL_set_fd" _ssl_set_fd :: Ptr SSL_ -> CInt -> IO ()

-- | Wrap a Socket in an SSL connection. Reading and writing to the Socket
--   after this will cause weird errors in the SSL code. The SSL object
--   carries a handle to the Socket so you need not worry about the garbage
--   collector closing the file descriptor out from under you.
connection :: SSLContext -> Socket -> IO SSL
connection context sock@(MkSocket fd _ _ _ _) = do
  sem <- newQSem 1
  ssl <- withContext context (\ctx -> do
    ssl <- _ssl_new ctx >>= failIfNull
    _ssl_set_fd ssl fd
    return ssl)
  fpssl <- newForeignPtr _ssl_free ssl
  return $ SSL (sem, fpssl, Fd fd, sock)

withSSL :: SSL -> (Ptr SSL_ -> IO a) -> IO a
withSSL (SSL (sem, ssl, _, _)) action = do
  waitQSem sem
  finally (withForeignPtr ssl action) $ signalQSem sem

foreign import ccall "SSL_accept" _ssl_accept :: Ptr SSL_ -> IO CInt
foreign import ccall "SSL_connect" _ssl_connect :: Ptr SSL_ -> IO CInt
foreign import ccall unsafe "SSL_get_error" _ssl_get_error :: Ptr SSL_ -> CInt -> IO CInt

sslErrorToString :: CInt -> String
sslErrorToString (#const SSL_ERROR_NONE) = "SSL: No error"
sslErrorToString (#const SSL_ERROR_ZERO_RETURN) = "SSL: connection cleanly closed"
sslErrorToString (#const SSL_ERROR_WANT_CONNECT) = "SSL: want connect"
sslErrorToString (#const SSL_ERROR_WANT_ACCEPT) = "SSL: want accept"
sslErrorToString (#const SSL_ERROR_WANT_X509_LOOKUP) = "SSL: want X509 lookup"
sslErrorToString (#const SSL_ERROR_SYSCALL) = "SSL: syscall error"
sslErrorToString (#const SSL_ERROR_SSL) = "SSL: ssl protocol error"
sslErrorToString x = "SSL: unknown error " ++ show x

-- | This is the type of an SSL IO operation. EOF and termination are handled
--   by exceptions while everything else is one of these. Note that reading
--   from an SSL socket can result in WantWrite and vice versa.
data SSLIOResult = Done CInt  -- ^ successfully mananged *n* bytes
                 | WantRead  -- ^ needs more data from the network
                 | WantWrite  -- ^ needs more outgoing buffer space
                 deriving (Eq)


-- | Perform an SSL operation which can return non-blocking error codes, thus
--   requesting that the operation be performed when data or buffer space is
--   availible.
sslDoHandshake :: (Ptr SSL_ -> IO CInt) -> SSL -> IO CInt
sslDoHandshake action ssl@(SSL (_, _, fd, _)) = do
  let f ssl = do
        n <- action ssl
        case n of
             n | n >= 0 -> return $ Done n
             _ -> do
               err <- _ssl_get_error ssl n
               case err of
                    (#const SSL_ERROR_WANT_READ) -> return WantRead
                    (#const SSL_ERROR_WANT_WRITE) -> return WantWrite
                    _ -> fail $ sslErrorToString err
  result <- withSSL ssl f
  case result of
       Done n -> return n
       WantRead -> threadWaitRead fd >> sslDoHandshake action ssl
       WantWrite -> threadWaitWrite fd >> sslDoHandshake action ssl

-- | Perform an SSL server handshake
accept :: SSL -> IO ()
accept ssl = sslDoHandshake _ssl_accept ssl >>= failIf (/= 1) >> return ()

-- | Perform an SSL client handshake
connect :: SSL -> IO ()
connect ssl = sslDoHandshake _ssl_connect ssl >>= failIf (/= 1) >> return ()

foreign import ccall "SSL_read" _ssl_read :: Ptr SSL_ -> Ptr Word8 -> CInt -> IO CInt
foreign import ccall unsafe "SSL_get_shutdown" _ssl_get_shutdown :: Ptr SSL_ -> IO CInt

-- | Perform an SSL operation which operates of a buffer and can return
--   non-blocking error codes, thus requesting that it be performed again when
--   more data or buffer space is availible.
--
--   Note that these SSL functions generally require that the arguments to the
--   repeated call be exactly the same. This presents an issue because multiple
--   threads could try writing at the same time (with different buffers) so the
--   calling function should probably hold the lock on the SSL object over the
--   whole time (include repeated calls)
sslIOInner :: (Ptr SSL_ -> Ptr Word8 -> CInt -> IO CInt)  -- ^ the SSL IO function to call
           -> Ptr CChar  -- ^ the buffer to pass
           -> Int  -- ^ the length to pass
           -> Ptr SSL_
           -> IO SSLIOResult
sslIOInner f ptr nbytes ssl = do
  n <- f ssl (castPtr ptr) $ fromIntegral nbytes
  case n of
       n | n > 0 -> return $ Done $ fromIntegral n
         | n == 0 -> do
           shutdown <- _ssl_get_shutdown ssl
           if shutdown .&. (#const SSL_RECEIVED_SHUTDOWN) == 0
              then fail "SSL connection abruptly terminated"
              else ioError $ mkIOError eofErrorType  "" Nothing Nothing
       _ -> do
           err <- _ssl_get_error ssl n
           case err of
                (#const SSL_ERROR_WANT_READ) -> return WantRead
                (#const SSL_ERROR_WANT_WRITE) -> return WantWrite
                _ -> fail $ sslErrorToString err

-- | Try the read the given number of bytes from an SSL connection. On EOF an
--   empty ByteString is returned. If the connection dies without a graceful
--   SSL shutdown, an exception is raised.
read :: SSL -> Int -> IO B.ByteString
read ssl@(SSL (_, _, fd, _)) nbytes = B.createAndTrim nbytes $ f ssl
    where
      f ssl ptr
          = do result <- withSSL ssl $ sslIOInner _ssl_read (castPtr ptr) nbytes
               case result of
                 Done n -> return $ fromIntegral n
                 WantRead -> threadWaitRead fd >> f ssl ptr
                 WantWrite -> threadWaitWrite fd >> f ssl ptr
            `catch`
            \ ioe ->
                if isEOFError ioe then
                    return 0
                else
                    ioError ioe -- rethrow

foreign import ccall "SSL_write" _ssl_write :: Ptr SSL_ -> Ptr Word8 -> CInt -> IO CInt

-- | Write a given ByteString to the SSL connection. Either all the data is
--   written or an exception is raised because of an error
write :: SSL -> B.ByteString -> IO ()
write ssl@(SSL (_, _, fd, _)) bs = B.unsafeUseAsCStringLen bs $ f ssl where
  f ssl (ptr, len) = do
    result <- withSSL ssl $ sslIOInner _ssl_write ptr len
    case result of
         Done _ -> return ()
         WantRead -> threadWaitRead fd >> f ssl (ptr, len)
         WantWrite -> threadWaitWrite fd >> f ssl (ptr, len)

-- | Lazily read all data until reaching EOF. If the connection dies
--   without a graceful SSL shutdown, an exception is raised.
lazyRead :: SSL -> IO L.ByteString
lazyRead ssl = lazyRead' >>= return . L.fromChunks
    where
      chunkSize = L.defaultChunkSize

      lazyRead' = unsafeInterleaveIO loop

      loop = do bs <- read ssl chunkSize
                if B.null bs then
                    -- got EOF
                    return []
                  else
                    do bss <- lazyRead'
                       return (bs:bss)

-- | Write a lazy ByteString to the SSL connection. In contrast to
--   'write', there is a chance that the string is written partway and
--   then an exception is raised for an error. The string doesn't
--   necessarily have to be finite.
lazyWrite :: SSL -> L.ByteString -> IO ()
lazyWrite ssl lbs
    = mapM_ (write ssl) $ L.toChunks lbs

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
shutdown ssl ty = do
  n <- sslDoHandshake _ssl_shutdown ssl
  case ty of
       Unidirectional -> return ()
       Bidirectional -> do
         if n == 1
            then return ()
            else shutdown ssl ty

foreign import ccall "SSL_get_peer_certificate" _ssl_get_peer_cert :: Ptr SSL_ -> IO (Ptr X509_)

-- | After a successful connection, get the certificate of the other party. If
--   this is a server connection, you probably won't get a certificate unless
--   you asked for it with contextSetVerificationMode
getPeerCertificate :: SSL -> IO (Maybe X509)
getPeerCertificate ssl =
  withSSL ssl $ \ssl -> do
    cert <- _ssl_get_peer_cert ssl
    if cert == nullPtr
       then return Nothing
       else wrapX509 cert >>= return . Just

foreign import ccall "SSL_get_verify_result" _ssl_get_verify_result :: Ptr SSL_ -> IO CLong

-- | Get the result of verifing the peer's certificate. This is mostly for
--   clients to verify the certificate of the server that they have connected
--   it. You must set a list of root CA certificates with contextSetCA... for
--   this to make sense.
--
--   Note that this returns True iff the peer's certificate has a valid chain
--   to a root CA. You also need to check that the certificate is correct (i.e.
--   has the correct hostname in it) with getPeerCertificate.
getVerifyResult :: SSL -> IO Bool
getVerifyResult ssl = do
  withSSL ssl $ \ssl -> do
    r <- _ssl_get_verify_result ssl
    return $ r == (#const X509_V_OK)

-- | Get the socket underlying an SSL connection
sslSocket :: SSL -> Socket
sslSocket (SSL (_, _, _, socket)) = socket
