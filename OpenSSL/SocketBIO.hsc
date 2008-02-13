-- | This module wraps a Haskell Socket in a BIO. It's different from the
--   @BIO@ module in that it works the 'other way' - gather than being the
--   client of a BIO, we are the implementation.
module OpenSSL.SocketBIO (socketToBIO) where

import Foreign
import Foreign.C
import Network.Socket (Socket(..))
import GHC.Conc (threadWaitRead, threadWaitWrite)

import OpenSSL.BIO (BIO, BIO_, wrapBioPtr)

foreign import ccall "socket_BIO_wrapper" _wrapper :: CInt -> IO (Ptr BIO_)

-- | Convert a Socket into a BIO object. Warning: the file descriptor
--   underlying this Socket is saved in the BIO, but it doesn't carry a
--   reference to the Socket itself. Thus, if you don't keep your own reference
--   then the GC could close the socket from under the BIO.
socketToBIO :: Socket -> IO BIO
socketToBIO (MkSocket s _ _ _ _) = _wrapper s >>= wrapBioPtr

foreign import ccall unsafe "send"
  c_send :: CInt -> Ptr a -> CSize -> CInt -> IO CInt
foreign import ccall unsafe "recv"
  c_recv :: CInt -> Ptr CChar -> CSize -> CInt -> IO CInt

--------------------------------------------------------------------------------
-- Taken from network-bytestring

{-# SPECIALISE
    throwErrnoIfMinus1Retry_mayBlock
         :: String -> IO CInt -> IO CInt -> IO CInt #-}
throwErrnoIfMinus1Retry_mayBlock :: Num a => String -> IO a -> IO a -> IO a
throwErrnoIfMinus1Retry_mayBlock name on_block act = do
    res <- act
    if res == -1
        then do
            err <- getErrno
            if err == eINTR
                then throwErrnoIfMinus1Retry_mayBlock name on_block act
                else if err == eWOULDBLOCK || err == eAGAIN
                        then on_block
                        else return (-1)
        else return res

throwErrnoIfMinus1Retry_repeatOnBlock :: Num a => String -> IO b -> IO a -> IO a
throwErrnoIfMinus1Retry_repeatOnBlock name on_block act = do
  throwErrnoIfMinus1Retry_mayBlock name (on_block >> repeat) act
  where repeat = throwErrnoIfMinus1Retry_repeatOnBlock name on_block act

--------------------------------------------------------------------------------
-- The following functions are callback Haskell functions which are exported to
-- the C code

bioRead :: CInt -> Ptr Word8 -> CInt -> IO CInt
bioRead fd ptr nbytes = do
  len <- throwErrnoIfMinus1Retry_repeatOnBlock "bioRead"
            (threadWaitRead (fromIntegral fd)) $
            c_recv fd (castPtr ptr) (fromIntegral nbytes) 0
  if fromIntegral len == (-1 :: Int)
     then do errno <- getErrno
             if errno == eINTR
                then bioRead fd ptr nbytes
                else return (-1)
     else return len

bioWrite :: CInt -> Ptr Word8 -> CInt -> IO CInt
bioWrite fd ptr nbytes = do
   len <- throwErrnoIfMinus1Retry_repeatOnBlock "bioWrite"
            (threadWaitWrite (fromIntegral fd)) $
            c_send fd (castPtr ptr) (fromIntegral nbytes) 0
   return len

foreign export ccall "bioRead" bioRead :: CInt -> Ptr Word8 -> CInt -> IO CInt
foreign export ccall "bioWrite" bioWrite :: CInt -> Ptr Word8 -> CInt -> IO CInt
