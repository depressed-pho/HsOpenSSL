{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.X509.Name
    ( X509_NAME

    , peekX509Name
    )
    where

import           Foreign
import           Foreign.C
import           OpenSSL.Objects
import           OpenSSL.Utils


data X509_NAME       = X509_NAME
data X509_NAME_ENTRY = X509_NAME_ENTRY

foreign import ccall unsafe "X509_NAME_new"
        _new :: IO (Ptr X509_NAME)

foreign import ccall unsafe "&X509_NAME_free"
        _free :: FunPtr (Ptr X509_NAME -> IO ())

foreign import ccall unsafe "X509_NAME_entry_count"
        _entry_count :: Ptr X509_NAME -> IO Int

foreign import ccall unsafe "X509_NAME_get_entry"
        _get_entry :: Ptr X509_NAME -> Int -> IO (Ptr X509_NAME_ENTRY)

foreign import ccall unsafe "X509_NAME_ENTRY_get_object"
        _ENTRY_get_object :: Ptr X509_NAME_ENTRY -> IO (Ptr ASN1_OBJECT)

foreign import ccall unsafe "X509_NAME_ENTRY_get_data"
        _ENTRY_get_data :: Ptr X509_NAME_ENTRY -> IO (Ptr ASN1_STRING)


peekX509Name :: Ptr X509_NAME -> Bool -> IO [(String, String)]
peekX509Name namePtr wantLongName
    = do count <- _entry_count namePtr >>= failIf (< 0)
         mapM peekEntry $ take count [0..]
    where
      peekEntry :: Int -> IO (String, String)
      peekEntry n
          = do ent <- _get_entry namePtr n  >>= failIfNull
               obj <- _ENTRY_get_object ent >>= failIfNull
               dat <- _ENTRY_get_data   ent >>= failIfNull

               nid <- obj2nid obj
               key <- if wantLongName then
                          nid2ln nid
                      else
                          nid2sn nid
               val <- peekASN1String dat

               return (key, val)
