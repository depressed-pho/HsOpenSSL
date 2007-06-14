{- -*- haskell -*- -}
module OpenSSL.BIO
    ( BIO
    , push
    , (==>)
    , joinAll

    , flush
    , eof

    , read
    , readBS
    , readLBS
    , gets
    , getsBS
    , getsLBS
    , write
    , writeBS
    , writeLBS

    , newBase64

    , newMD

    , newMemBuf
    , newConstMemBuf
    , newConstMemBufBS
    , newConstMemBufLBS

    , newNullBIO
    )
    where

#include "HsOpenSSL.h"

import           Control.Monad
import qualified Data.ByteString as B
import           Data.ByteString.Base
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Foreign hiding (new)
import           Foreign.C
import qualified GHC.ForeignPtr as GF
import           OpenSSL.EVP
import           OpenSSL.Utils
import           Prelude hiding (read)
import           System.IO.Unsafe

{- bio ---------------------------------------------------------------------- -}

newtype BioMethod     = BioMethod (Ptr ())
type    BioMethod_ptr = Ptr ()

newtype BIO     = BIO (ForeignPtr ())
type    BIO_ptr = Ptr ()

foreign import ccall unsafe "BIO_new"
        _new :: BioMethod_ptr -> IO BIO_ptr

foreign import ccall unsafe "&BIO_free"
        _free :: FunPtr (BIO_ptr -> IO ())

foreign import ccall unsafe "BIO_push"
        _push :: BIO_ptr -> BIO_ptr -> IO BIO_ptr

foreign import ccall unsafe "HsOpenSSL_BIO_set_flags"
        _set_flags :: BIO_ptr -> Int -> IO ()


new :: BioMethod -> IO BIO
new (BioMethod method)
    = do ptr <- _new method
         failIfNull ptr
         liftM BIO $ newForeignPtr _free ptr


-- a の後ろに b を付ける。a の參照だけ保持してそこに書き込む事も、b の
-- 參照だけ保持してそこから讀み出す事も、兩方考へられるので、双方の
-- ForeignPtr が双方を touch する。參照カウント方式ではないから循環參照
-- しても問題無い。
push :: BIO -> BIO -> IO ()
push (BIO a) (BIO b)
    = withForeignPtr a $ \ aPtr ->
      withForeignPtr b $ \ bPtr ->
      do _push aPtr bPtr
         GF.addForeignPtrConcFinalizer a $ touchForeignPtr b
         GF.addForeignPtrConcFinalizer b $ touchForeignPtr a
         return ()


(==>) = push


joinAll :: [BIO] -> IO ()
joinAll []       = return ()
joinAll (_:[])   = return ()
joinAll (a:b:xs) = push a b >> joinAll (b:xs)


setFlags :: BIO -> Int -> IO ()
setFlags (BIO bio) flags
    = withForeignPtr bio $ \ bioPtr ->
      _set_flags bioPtr flags


{- ctrl --------------------------------------------------------------------- -}

foreign import ccall unsafe "HsOpenSSL_BIO_flush"
        _flush :: BIO_ptr -> IO Int

foreign import ccall unsafe "HsOpenSSL_BIO_eof"
        _eof :: BIO_ptr -> IO Int


flush :: BIO -> IO ()
flush (BIO bio)
    = withForeignPtr bio $ \ bioPtr ->
      do ret <- _flush bioPtr
         ret `failIf` (/= 1)
         return ()


eof :: BIO -> IO Bool
eof (BIO bio)
    = withForeignPtr bio $ \ bioPtr ->
      do ret <- _eof bioPtr
         return $ ret == 1


{- I/O ---------------------------------------------------------------------- -}

foreign import ccall unsafe "BIO_read"
        _read :: BIO_ptr -> Ptr CChar -> Int -> IO Int

foreign import ccall unsafe "BIO_gets"
        _gets :: BIO_ptr -> Ptr CChar -> Int -> IO Int

foreign import ccall unsafe "BIO_write"
        _write :: BIO_ptr -> Ptr CChar -> Int -> IO Int


read :: BIO -> IO String
read bio
    = liftM L8.unpack $ readLBS bio


readBS :: BIO -> Int -> IO ByteString
readBS (BIO bio) maxLen
    = withForeignPtr bio $ \ bioPtr ->
      createAndTrim maxLen $ \ buf ->
      do ret <- _read bioPtr (unsafeCoercePtr buf) maxLen
         interpret ret
    where
      interpret :: Int -> IO Int
      interpret n
          | n ==  0   = return 0
          | n == -1   = return 0
          | n <  -1   = raiseOpenSSLError
          | otherwise = return n


readLBS :: BIO -> IO LazyByteString
readLBS (BIO bio) = lazyRead >>= return . LPS
    where
      chunkSize = 32 * 1024
      
      lazyRead = unsafeInterleaveIO loop

      loop = do bs <- readBS (BIO bio) chunkSize
                if B.null bs then
                    do isEOF <- eof (BIO bio)
                       if isEOF then
                           return []
                         else
                           loop
                  else
                    do bss <- lazyRead
                       return (bs:bss)


gets :: BIO -> Int -> IO String
gets bio maxLen
    = liftM B8.unpack (getsBS bio maxLen)


getsBS :: BIO -> Int -> IO ByteString
getsBS (BIO bio) maxLen
    = withForeignPtr bio $ \ bioPtr ->
      createAndTrim maxLen $ \ buf ->
      do ret <- _gets bioPtr (unsafeCoercePtr buf) maxLen
         interpret ret
    where
      interpret :: Int -> IO Int
      interpret n
          | n ==  0   = return 0
          | n == -1   = return 0
          | n <  -1   = raiseOpenSSLError
          | otherwise = return n


getsLBS :: BIO -> Int -> IO LazyByteString
getsLBS bio maxLen
    = getsBS bio maxLen >>= \ bs -> (return . LPS) [bs]


write :: BIO -> String -> IO ()
write bio str
    = (return . L8.pack) str >>= writeLBS bio


writeBS :: BIO -> ByteString -> IO ()
writeBS (BIO bio) bs
    = withForeignPtr bio $ \ bioPtr ->
      unsafeUseAsCStringLen bs $ \ (buf, len) ->
      do ret <- _write bioPtr buf len
         interpret ret
    where
      interpret :: Int -> IO ()
      interpret n
          | n == B.length bs = return ()
          | n == -1          = writeBS (BIO bio) bs -- full retry
          | n <  -1          = raiseOpenSSLError
          | otherwise        = writeBS (BIO bio) (B.drop n bs) -- partial retry


writeLBS :: BIO -> LazyByteString -> IO ()
writeLBS bio (LPS chunks)
    = mapM_ (writeBS bio) chunks
      

{- base64 ------------------------------------------------------------------- -}

foreign import ccall unsafe "BIO_f_base64"
        _f_base64 :: IO BioMethod_ptr

foreign import ccall unsafe "HsOpenSSL_BIO_FLAGS_BASE64_NO_NL"
        _FLAGS_BASE64_NO_NL :: Int


f_base64 :: IO BioMethod
f_base64 = _f_base64 >>= return . BioMethod


newBase64 :: Bool -> IO BIO
newBase64 noNL
    = do bio <- new =<< f_base64
         when noNL $ setFlags bio _FLAGS_BASE64_NO_NL
         return bio


{- md ----------------------------------------------------------------------- -}

foreign import ccall unsafe "BIO_f_md"
        _f_md :: IO BioMethod_ptr

foreign import ccall unsafe "HsOpenSSL_BIO_set_md"
        _set_md :: BIO_ptr -> Ptr () -> IO Int


f_md :: IO BioMethod
f_md = _f_md >>= return . BioMethod


newMD :: EvpMD -> IO BIO
newMD (EvpMD md)
    = do BIO bio <- new =<< f_md
         withForeignPtr bio $ \ bioPtr ->
             do ret <- _set_md bioPtr md
                ret `failIf` (/= 1)
                return $ BIO bio


{- mem ---------------------------------------------------------------------- -}

foreign import ccall unsafe "BIO_s_mem"
        _s_mem :: IO BioMethod_ptr

foreign import ccall unsafe "BIO_new_mem_buf"
        _new_mem_buf :: Ptr CChar -> Int -> IO BIO_ptr


s_mem :: IO BioMethod
s_mem = _s_mem >>= return . BioMethod


newMemBuf :: IO BIO
newMemBuf = s_mem >>= new


newConstMemBuf :: String -> IO BIO
newConstMemBuf str
    = (return . B8.pack) str >>= newConstMemBufBS


-- ByteString への參照を BIO の finalizer に持たせる。
newConstMemBufBS :: ByteString -> IO BIO
newConstMemBufBS bs
    = let (foreignBuf, off, len) = toForeignPtr bs
      in
        withForeignPtr foreignBuf $ \ buf ->
        do bioPtr <- _new_mem_buf (unsafeCoercePtr $ buf `plusPtr` off) len
           failIfNull bioPtr

           bio <- newForeignPtr _free bioPtr
           GF.addForeignPtrConcFinalizer bio $ touchForeignPtr foreignBuf
           
           return $ BIO bio


newConstMemBufLBS :: LazyByteString -> IO BIO
newConstMemBufLBS (LPS bss)
    = (return . B.concat) bss >>= newConstMemBufBS

{- null --------------------------------------------------------------------- -}

foreign import ccall unsafe "BIO_s_null"
        _s_null :: IO BioMethod_ptr


s_null :: IO BioMethod
s_null = liftM BioMethod _s_null


newNullBIO :: IO BIO
newNullBIO = s_null >>= new