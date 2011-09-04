{-# OPTIONS_GHC -fno-warn-name-shadowing #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE NamedFieldPuns #-}
-- | Functions for handling SSL connections. These functions use GHC specific
--   calls to cooperative the with the scheduler so that 'blocking' functions
--   only actually block the Haskell thread, not a whole OS thread.
module OpenSSL.Session
  ( -- * Contexts
    SSLContext
  , context
  , contextSetPrivateKey
  , contextSetCertificate
  , contextSetPrivateKeyFile
  , contextSetCertificateFile
  , contextSetCiphers
  , contextSetDefaultCiphers
  , contextCheckPrivateKey
  , VerificationMode(..)
  , contextSetVerificationMode
  , contextSetCAFile
  , contextSetCADirectory
  , contextGetCAStore

    -- * SSL connections
  , SSL
  , SSLResult(..)
  , connection
  , fdConnection
  , accept
  , tryAccept
  , connect
  , tryConnect
  , read
  , tryRead
  , write
  , tryWrite
  , lazyRead
  , lazyWrite
  , shutdown
  , tryShutdown
  , ShutdownType(..)
  , getPeerCertificate
  , getVerifyResult
  , sslSocket
  , sslFd

    -- * SSL Exceptions
  , SomeSSLException
  , ConnectionCleanlyClosed
  , ConnectionAbruptlyTerminated
  , WantConnect
  , WantAccept
  , WantX509Lookup
  , SSLIOError
  , ProtocolError
  , UnknownError(..)
  ) where

#include "openssl/ssl.h"

import Prelude hiding (catch, read, ioError, mapM, mapM_)
import Control.Concurrent (threadWaitWrite, threadWaitRead)
import Control.Concurrent.QSem
import Control.Exception
import Control.Applicative ((<$>), (<$))
import Control.Monad (unless)
import Data.Typeable
import Data.Foldable (Foldable, mapM_, forM_)
import Data.Traversable (Traversable, mapM, forM)
import Data.Maybe (fromMaybe)
import Data.IORef
import Foreign hiding (void)
import Foreign.C
import qualified Foreign.Concurrent as FC
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.IO.Error (mkIOError, eofErrorType, isEOFError)
import System.IO.Unsafe
import System.Posix.Types (Fd(..))
import Network.Socket (Socket(..))

import OpenSSL.EVP.PKey
import OpenSSL.Utils
import OpenSSL.X509 (X509, X509_, wrapX509, withX509Ptr)
import OpenSSL.X509.Store

type VerifyCb = Bool -> Ptr X509_STORE_CTX -> IO Bool

foreign import ccall "wrapper" mkVerifyCb :: VerifyCb -> IO (FunPtr VerifyCb)

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
data SSLContext = SSLContext { ctxSem  :: QSem
                             , ctxPtr  :: ForeignPtr SSLContext_
                             , ctxVfCb :: IORef (Maybe (FunPtr VerifyCb))
                             }

data SSLMethod_

foreign import ccall unsafe "SSL_CTX_new" _ssl_ctx_new :: Ptr SSLMethod_ -> IO (Ptr SSLContext_)
foreign import ccall unsafe "SSL_CTX_free" _ssl_ctx_free :: Ptr SSLContext_ -> IO ()
foreign import ccall unsafe "SSLv23_method" _ssl_method :: IO (Ptr SSLMethod_)

-- | Create a new SSL context.
context :: IO SSLContext
context = do
  ctx   <- _ssl_method >>= _ssl_ctx_new
  cbRef <- newIORef Nothing
  ptr   <- FC.newForeignPtr ctx $ do
    _ssl_ctx_free ctx
    readIORef cbRef >>= mapM_ freeHaskellFunPtr
  sem   <- newQSem 1
  return $ SSLContext { ctxSem = sem, ctxPtr = ptr, ctxVfCb = cbRef }

-- | Run the given action with the raw context pointer and obtain the lock
--   while doing so.
withContext :: SSLContext -> (Ptr SSLContext_ -> IO a) -> IO a
withContext (SSLContext {ctxSem, ctxPtr}) action = do
  waitQSem ctxSem
  finally (withForeignPtr ctxPtr action) $ signalQSem ctxSem

touchContext :: SSLContext -> IO ()
touchContext = touchForeignPtr . ctxPtr

contextLoadFile :: (Ptr SSLContext_ -> CString -> CInt -> IO CInt)
                -> SSLContext -> String -> IO ()
contextLoadFile f context path =
  withContext context $ \ctx ->
    withCString path $ \cpath -> do
      result <- f ctx cpath (#const SSL_FILETYPE_PEM)
      unless (result == 1)
          $ f ctx cpath (#const SSL_FILETYPE_ASN1) >>= failIf_ (/= 1)

foreign import ccall unsafe "SSL_CTX_use_PrivateKey"
    _ssl_ctx_use_privatekey :: Ptr SSLContext_ -> Ptr EVP_PKEY -> IO CInt
foreign import ccall unsafe "SSL_CTX_use_certificate"
    _ssl_ctx_use_certificate :: Ptr SSLContext_ -> Ptr X509_ -> IO CInt

-- | Install a private key into a context.
contextSetPrivateKey :: KeyPair k => SSLContext -> k -> IO ()
contextSetPrivateKey context key
    = withContext context $ \ ctx    ->
      withPKeyPtr' key    $ \ keyPtr ->
          _ssl_ctx_use_privatekey ctx keyPtr
               >>= failIf_ (/= 1)

-- | Install a certificate (public key) into a context.
contextSetCertificate :: SSLContext -> X509 -> IO ()
contextSetCertificate context cert
    = withContext context $ \ ctx     ->
      withX509Ptr cert    $ \ certPtr ->
          _ssl_ctx_use_certificate ctx certPtr
               >>= failIf_ (/= 1)

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
      _ssl_ctx_set_cipher_list ctx cpath >>= failIf_ (/= 1)

contextSetDefaultCiphers :: SSLContext -> IO ()
contextSetDefaultCiphers = flip contextSetCiphers "DEFAULT"

foreign import ccall unsafe "SSL_CTX_check_private_key"
   _ssl_ctx_check_private_key :: Ptr SSLContext_ -> IO CInt

-- | Return true iff the private key installed in the given context matches the
--   certificate also installed.
contextCheckPrivateKey :: SSLContext -> IO Bool
contextCheckPrivateKey context =
  withContext context $ \ctx ->
    fmap (== 1) (_ssl_ctx_check_private_key ctx)

-- | See <http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html>
data VerificationMode = VerifyNone
                      | VerifyPeer {
                          vpFailIfNoPeerCert :: Bool  -- ^ is a certificate required
                        , vpClientOnce       :: Bool  -- ^ only request once per connection
                        , vpCallback         :: Maybe (Bool -> X509StoreCtx -> IO Bool) -- ^ optional callback
                        }

foreign import ccall unsafe "SSL_CTX_set_verify"
   _ssl_set_verify_mode :: Ptr SSLContext_ -> CInt -> FunPtr VerifyCb -> IO ()

contextSetVerificationMode :: SSLContext -> VerificationMode -> IO ()
contextSetVerificationMode context VerifyNone =
  withContext context $ \ctx ->
    _ssl_set_verify_mode ctx (#const SSL_VERIFY_NONE) nullFunPtr >> return ()

contextSetVerificationMode context (VerifyPeer reqp oncep cbp) = do
  let mode = (#const SSL_VERIFY_PEER) .|.
             (if reqp then (#const SSL_VERIFY_FAIL_IF_NO_PEER_CERT) else 0) .|.
             (if oncep then (#const SSL_VERIFY_CLIENT_ONCE) else 0)
  withContext context $ \ctx -> do
    let cbRef = ctxVfCb context
    newCb <- mapM mkVerifyCb $ (<$> cbp) $ \cb pvf pStoreCtx ->
      cb pvf =<< wrapX509StoreCtx (return ()) pStoreCtx
    oldCb <- readIORef cbRef
    writeIORef cbRef newCb
    forM_ oldCb freeHaskellFunPtr
    _ssl_set_verify_mode ctx mode $ fromMaybe nullFunPtr newCb
    return ()

foreign import ccall unsafe "SSL_CTX_load_verify_locations"
  _ssl_load_verify_locations :: Ptr SSLContext_ -> Ptr CChar -> Ptr CChar -> IO CInt

-- | Set the location of a PEM encoded list of CA certificates to be used when
--   verifying a server's certificate
contextSetCAFile :: SSLContext -> FilePath -> IO ()
contextSetCAFile context path =
  withContext context $ \ctx ->
    withCString path $ \cpath ->
        _ssl_load_verify_locations ctx cpath nullPtr >>= failIf_ (/= 1)

-- | Set the path to a directory which contains the PEM encoded CA root
--   certificates. This is an alternative to 'contextSetCAFile'. See
--   <http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html> for
--   details of the file naming scheme
contextSetCADirectory :: SSLContext -> FilePath -> IO ()
contextSetCADirectory context path =
  withContext context $ \ctx ->
    withCString path $ \cpath ->
        _ssl_load_verify_locations ctx nullPtr cpath >>= failIf_ (/= 1)

foreign import ccall unsafe "SSL_CTX_get_cert_store"
  _ssl_get_cert_store :: Ptr SSLContext_ -> IO (Ptr X509_STORE)

-- | Get a reference to, not a copy of, the X.509 certificate storage
--   in the SSL context.
contextGetCAStore :: SSLContext -> IO X509Store
contextGetCAStore context
    = withContext context $ \ ctx ->
      _ssl_get_cert_store ctx
           >>= wrapX509Store (touchContext context)


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
data SSL = SSL { sslSem    :: QSem
               , sslPtr    :: ForeignPtr SSL_
               , sslFd     :: Fd -- ^ Get the underlying socket Fd
               , sslSocket :: Maybe Socket -- ^ Get the socket underlying an SSL connection
               }

foreign import ccall unsafe "SSL_new" _ssl_new :: Ptr SSLContext_ -> IO (Ptr SSL_)
foreign import ccall unsafe "&SSL_free" _ssl_free :: FunPtr (Ptr SSL_ -> IO ())
foreign import ccall unsafe "SSL_set_fd" _ssl_set_fd :: Ptr SSL_ -> CInt -> IO ()

connection' :: SSLContext -> Fd -> Maybe Socket -> IO SSL
connection' context fd@(Fd fdInt) sock = do
  sem <- newQSem 1
  ssl <- withContext context $ \ctx -> do
    ssl <- _ssl_new ctx >>= failIfNull
    _ssl_set_fd ssl fdInt
    return ssl
  fpssl <- newForeignPtr _ssl_free ssl
  return $ SSL { sslSem    = sem
               , sslPtr    = fpssl
               , sslFd     = fd
               , sslSocket = sock
               }

-- | Wrap a Socket in an SSL connection. Reading and writing to the Socket
--   after this will cause weird errors in the SSL code. The SSL object
--   carries a handle to the Socket so you need not worry about the garbage
--   collector closing the file descriptor out from under you.
connection :: SSLContext -> Socket -> IO SSL
connection context sock@(MkSocket fd _ _ _ _) =
  connection' context (Fd fd) (Just sock)

-- | Wrap a socket Fd in an SSL connection.
fdConnection :: SSLContext -> Fd -> IO SSL
fdConnection context fd = connection' context fd Nothing

withSSL :: SSL -> (Ptr SSL_ -> IO a) -> IO a
withSSL (SSL {sslSem, sslPtr}) action = do
  waitQSem sslSem
  finally (withForeignPtr sslPtr action) $ signalQSem sslSem

foreign import ccall "SSL_accept" _ssl_accept :: Ptr SSL_ -> IO CInt
foreign import ccall "SSL_connect" _ssl_connect :: Ptr SSL_ -> IO CInt
foreign import ccall unsafe "SSL_get_error" _ssl_get_error :: Ptr SSL_ -> CInt -> IO CInt

throwSSLException :: CInt -> IO a
throwSSLException (#const SSL_ERROR_ZERO_RETURN     ) = throw ConnectionCleanlyClosed
throwSSLException (#const SSL_ERROR_WANT_CONNECT    ) = throw WantConnect
throwSSLException (#const SSL_ERROR_WANT_ACCEPT     ) = throw WantAccept
throwSSLException (#const SSL_ERROR_WANT_X509_LOOKUP) = throw WantX509Lookup
throwSSLException (#const SSL_ERROR_SYSCALL         ) = throw SSLIOError
throwSSLException (#const SSL_ERROR_SSL             ) = throw ProtocolError
throwSSLException x = throw (UnknownError (fromIntegral x))

-- | This is the type of an SSL IO operation. EOF and termination are handled
--   by exceptions while everything else is one of these. Note that reading
--   from an SSL socket can result in WantWrite and vice versa.
data SSLResult a = SSLDone a  -- ^ operation finished successfully
                 | WantRead  -- ^ needs more data from the network
                 | WantWrite  -- ^ needs more outgoing buffer space
                 deriving (Eq, Show, Functor, Foldable, Traversable)

-- | Block until the operation is finished.
sslBlock :: (SSL -> IO (SSLResult a)) -> SSL -> IO a
sslBlock action ssl = do
  result <- action ssl
  case result of
    SSLDone r -> return r
    WantRead  -> threadWaitRead  (sslFd ssl) >> sslBlock action ssl
    WantWrite -> threadWaitWrite (sslFd ssl) >> sslBlock action ssl

-- | Perform an SSL operation which can return non-blocking error codes, thus
--   requesting that the operation be performed when data or buffer space is
--   availible.
sslTryHandshake :: (Ptr SSL_ -> IO CInt) -> SSL -> IO (SSLResult CInt)
sslTryHandshake action = flip withSSL $ \pSsl -> do
  n <- action pSsl
  if n >= 0
    then return $ SSLDone n
    else do
      err <- _ssl_get_error pSsl n
      case err of
        (#const SSL_ERROR_WANT_READ)  -> return WantRead
        (#const SSL_ERROR_WANT_WRITE) -> return WantWrite
        _ -> throwSSLException err

-- | Perform an SSL server handshake
accept :: SSL -> IO ()
accept = sslBlock tryAccept

-- | Try to perform an SSL server handshake without blocking
tryAccept :: SSL -> IO (SSLResult ())
tryAccept ssl = do
  result <- sslTryHandshake _ssl_accept ssl
  forM result $ failIf_ (/= 1)

-- | Perform an SSL client handshake
connect :: SSL -> IO ()
connect = sslBlock tryConnect

-- | Try to perform an SSL client handshake without blocking
tryConnect :: SSL -> IO (SSLResult ())
tryConnect ssl = do
  result <- sslTryHandshake _ssl_connect ssl
  forM result $ failIf_ (/= 1)

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
           -> IO (SSLResult CInt)
sslIOInner f ptr nbytes ssl = do
  n <- f ssl (castPtr ptr) $ fromIntegral nbytes
  case n of
       n | n > 0 -> return $ SSLDone $ fromIntegral n
         | n == 0 -> do
           shutdown <- _ssl_get_shutdown ssl
           if shutdown .&. (#const SSL_RECEIVED_SHUTDOWN) == 0
              then throw ConnectionAbruptlyTerminated
              else ioError $ mkIOError eofErrorType  "" Nothing Nothing
       _ -> do
           err <- _ssl_get_error ssl n
           case err of
                (#const SSL_ERROR_WANT_READ) -> return WantRead
                (#const SSL_ERROR_WANT_WRITE) -> return WantWrite
                _ -> throwSSLException err

catchEOF :: a -> IO a -> IO a
catchEOF x m = m `catch` \e -> if isEOFError e then return x else throwIO e

-- | Try to read the given number of bytes from an SSL connection. On EOF an
--   empty ByteString is returned. If the connection dies without a graceful
--   SSL shutdown, an exception is raised.
read :: SSL -> Int -> IO B.ByteString
read ssl nbytes = B.createAndTrim nbytes $ \ptr -> do
  let doRead = withSSL ssl $ sslIOInner _ssl_read (castPtr ptr) nbytes
  catchEOF 0 $ fromIntegral <$> sslBlock (const doRead) ssl

-- | Try to read the given number of bytes from an SSL connection
--   without blocking.
tryRead :: SSL -> Int -> IO (SSLResult B.ByteString)
tryRead ssl nbytes = do
  (bs, result) <- B.createAndTrim' nbytes $ \ptr -> do
    result <- catchEOF (SSLDone 0) $ withSSL ssl $
                sslIOInner _ssl_read (castPtr ptr) nbytes
    return $ case result of
      SSLDone n -> (0, fromIntegral n, SSLDone ())
      WantRead  -> (0, 0,              WantRead)
      WantWrite -> (0, 0,              WantWrite)
  return $ bs <$ result

foreign import ccall "SSL_write" _ssl_write :: Ptr SSL_ -> Ptr Word8 -> CInt -> IO CInt

-- | Write a given ByteString to the SSL connection. Either all the data is
--   written or an exception is raised because of an error
write :: SSL -> B.ByteString -> IO ()
write ssl bs = sslBlock (`tryWrite` bs) ssl >> return ()

-- | Try to write a given ByteString to the SSL connection without blocking.
tryWrite :: SSL -> B.ByteString -> IO (SSLResult ())
tryWrite ssl bs =
  B.unsafeUseAsCStringLen bs $ \(ptr, len) ->
    ((() <$) <$>) $ withSSL ssl $ sslIOInner _ssl_write ptr len

-- | Lazily read all data until reaching EOF. If the connection dies
--   without a graceful SSL shutdown, an exception is raised.
lazyRead :: SSL -> IO L.ByteString
lazyRead ssl = fmap L.fromChunks lazyRead'
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
shutdown ssl ty = sslBlock (`tryShutdown` ty) ssl

-- | Try to cleanly shutdown an SSL connection without blocking.
tryShutdown :: SSL -> ShutdownType -> IO (SSLResult ())
tryShutdown ssl ty = do
  result <- sslTryHandshake _ssl_shutdown ssl
  case result of
    SSLDone n -> case ty of
      Bidirectional | n /= 1 -> tryShutdown ssl ty
      _ -> return $ SSLDone ()
    WantRead  -> return WantRead
    WantWrite -> return WantWrite

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
       else fmap Just (wrapX509 cert)

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
getVerifyResult ssl =
  withSSL ssl $ \ssl -> do
    r <- _ssl_get_verify_result ssl
    return $ r == (#const X509_V_OK)

-- | The root exception type for all SSL exceptions.
data SomeSSLException
    = forall e. Exception e => SomeSSLException e
      deriving Typeable

instance Show SomeSSLException where
    show (SomeSSLException e) = show e

instance Exception SomeSSLException

sslExceptionToException :: Exception e => e -> SomeException
sslExceptionToException = toException . SomeSSLException

sslExceptionFromException :: Exception e => SomeException -> Maybe e
sslExceptionFromException x
    = do SomeSSLException a <- fromException x
         cast a

-- | The TLS\/SSL connection has been closed. If the protocol version
-- is SSL 3.0 or TLS 1.0, this result code is returned only if a
-- closure alert has occurred in the protocol, i.e. if the connection
-- has been closed cleanly. Note that in this case
-- 'ConnectionCleanlyClosed' does not necessarily indicate that the
-- underlying transport has been closed.
data ConnectionCleanlyClosed
    = ConnectionCleanlyClosed
      deriving (Typeable, Show, Eq)

instance Exception ConnectionCleanlyClosed where
    toException   = sslExceptionToException
    fromException = sslExceptionFromException

-- | The peer uncleanly terminated the connection without sending the
-- \"close notify\" alert.
data ConnectionAbruptlyTerminated
    = ConnectionAbruptlyTerminated
      deriving (Typeable, Show, Eq)

instance Exception ConnectionAbruptlyTerminated where
    toException   = sslExceptionToException
    fromException = sslExceptionFromException

-- | The operation did not complete; the same TLS\/SSL I\/O function
-- should be called again later. The underlying socket was not
-- connected yet to the peer and the call would block in
-- 'connect'. The SSL function should be called again when the
-- connection is established. This message can only appear with
-- 'connect'.
data WantConnect
    = WantConnect
      deriving (Typeable, Show, Eq)

instance Exception WantConnect where
    toException   = sslExceptionToException
    fromException = sslExceptionFromException

-- | The operation did not complete; the same TLS\/SSL I\/O function
-- should be called again later. The underlying socket was not
-- connected yet to the peer and the call would block in 'accept'. The
-- SSL function should be called again when the connection is
-- established. This message can only appear with 'accept'.
data WantAccept
    = WantAccept
      deriving (Typeable, Show, Eq)

instance Exception WantAccept where
    toException   = sslExceptionToException
    fromException = sslExceptionFromException

-- | The operation did not complete because an application callback
-- set by SSL_CTX_set_client_cert_cb() has asked to be called
-- again. The TLS\/SSL I\/O function should be called again
-- later. Details depend on the application.
data WantX509Lookup
    = WantX509Lookup
      deriving (Typeable, Show, Eq)

instance Exception WantX509Lookup where
    toException   = sslExceptionToException
    fromException = sslExceptionFromException

-- | Some I\/O error occurred. The OpenSSL error queue may contain
-- more information on the error. If the error queue is empty
-- (i.e. ERR_get_error() returns 0), ret can be used to find out more
-- about the error: If ret == 0, an EOF was observed that violates the
-- protocol. If ret == -1, the underlying BIO reported an I\/O error
-- (for socket I\/O on Unix systems, consult errno for details).
data SSLIOError
    = SSLIOError
      deriving (Typeable, Show, Eq)

instance Exception SSLIOError where
    toException   = sslExceptionToException
    fromException = sslExceptionFromException

-- | A failure in the SSL library occurred, usually a protocol
-- error. The OpenSSL error queue contains more information on the
-- error.
data ProtocolError
    = ProtocolError
      deriving (Typeable, Show, Eq)

instance Exception ProtocolError where
    toException   = sslExceptionToException
    fromException = sslExceptionFromException

-- | SSL_get_error() returned an error code which is unknown to this
-- library.
data UnknownError
    = UnknownError !Int
      deriving (Typeable, Show, Eq)

instance Exception UnknownError where
    toException   = sslExceptionToException
    fromException = sslExceptionFromException
