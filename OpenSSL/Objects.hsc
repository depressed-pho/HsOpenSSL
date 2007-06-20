{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.Objects
    ( ObjNameType(..)
    , getObjNames

    , ASN1_OBJECT
    , obj2nid
    , nid2sn
    , nid2ln

    , ASN1_STRING
    , peekASN1String

    , ASN1_INTEGER
    , peekASN1Integer

    , ASN1_TIME
    , peekASN1Time
    )
    where

import           Control.Monad
import           Data.IORef
import           Foreign
import           Foreign.C
import           OpenSSL.BIO
import           OpenSSL.BN
import           OpenSSL.Utils


type ObjName  = Ptr OBJ_NAME
data OBJ_NAME = OBJ_NAME

type DoAllCallback = ObjName -> Ptr () -> IO ()


foreign import ccall safe "OBJ_NAME_do_all"
        _NAME_do_all :: Int -> FunPtr DoAllCallback -> Ptr () -> IO ()

foreign import ccall safe "OBJ_NAME_do_all_sorted"
        _NAME_do_all_sorted :: Int -> FunPtr DoAllCallback -> Ptr () -> IO ()

foreign import ccall "wrapper"
        mkDoAllCallback :: DoAllCallback -> IO (FunPtr DoAllCallback)


data ObjNameType = MDMethodType
                 | CipherMethodType
                 | PKeyMethodType
                 | CompMethodType

objNameTypeToInt :: ObjNameType -> Int
objNameTypeToInt MDMethodType     = #const OBJ_NAME_TYPE_MD_METH
objNameTypeToInt CipherMethodType = #const OBJ_NAME_TYPE_CIPHER_METH
objNameTypeToInt PKeyMethodType   = #const OBJ_NAME_TYPE_PKEY_METH
objNameTypeToInt CompMethodType   = #const OBJ_NAME_TYPE_COMP_METH


iterateObjNames :: ObjNameType -> Bool -> (ObjName -> IO ()) -> IO ()
iterateObjNames nameType wantSorted cb
    = do cbPtr <- mkDoAllCallback $ \ name _ -> cb name
         let action = if wantSorted then
                          _NAME_do_all_sorted
                      else
                          _NAME_do_all
         action (objNameTypeToInt nameType) cbPtr nullPtr
         freeHaskellFunPtr cbPtr


objNameStr :: ObjName -> IO String
objNameStr name
    = do strPtr <- (#peek OBJ_NAME, name) name
         peekCString strPtr


getObjNames :: ObjNameType -> Bool -> IO [String]
getObjNames nameType wantSorted
    = do listRef <- newIORef []
         iterateObjNames nameType wantSorted $ \ name ->
             do nameStr <- objNameStr name
                modifyIORef listRef (++ [nameStr])
         readIORef listRef


{- ASN1_OBJECT --------------------------------------------------------------- -}

data ASN1_OBJECT = ASN1_OBJECT

foreign import ccall unsafe "OBJ_obj2nid"
        obj2nid :: Ptr ASN1_OBJECT -> IO Int

foreign import ccall unsafe "OBJ_nid2sn"
        _nid2sn :: Int -> IO CString

foreign import ccall unsafe "OBJ_nid2ln"
        _nid2ln :: Int -> IO CString


nid2sn :: Int -> IO String
nid2sn nid = _nid2sn nid >>= peekCString


nid2ln :: Int -> IO String
nid2ln nid = _nid2ln nid >>= peekCString


{- ASN1_STRING --------------------------------------------------------------- -}

data ASN1_STRING = ASN1_STRING

peekASN1String :: Ptr ASN1_STRING -> IO String
peekASN1String strPtr
    = do buf <- (#peek ASN1_STRING, data  ) strPtr
         len <- (#peek ASN1_STRING, length) strPtr
         peekCStringLen (buf, len)


{- ASN1_INTEGER -------------------------------------------------------------- -}

data ASN1_INTEGER = ASN1_INTEGER

foreign import ccall unsafe "ASN1_INTEGER_to_BN"
        _ASN1_INTEGER_to_BN :: Ptr ASN1_INTEGER -> BigNum -> IO BigNum


peekASN1Integer :: Ptr ASN1_INTEGER -> IO Integer
peekASN1Integer intPtr
    = do bn  <- _ASN1_INTEGER_to_BN intPtr nullPtr
         dec <- bn2dec bn
         freeBN bn
         return dec

{- ASN1_TIME ---------------------------------------------------------------- -}

data ASN1_TIME = ASN1_TIME

foreign import ccall unsafe "ASN1_TIME_print"
        _ASN1_TIME_print :: Ptr BIO_ -> Ptr ASN1_TIME -> IO Int


-- This action should return ClockTime or something but that is
-- extremely difficult...
peekASN1Time :: Ptr ASN1_TIME -> IO String
peekASN1Time time
    = do bio <- newMem
         withForeignPtr bio $ \ bioPtr ->
             _ASN1_TIME_print bioPtr time
                  >>= failIf (/= 1)
         bioRead bio
