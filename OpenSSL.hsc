{- -*- haskell -*- -}

-- |HsOpenSSL is a (part of) OpenSSL binding for Haskell. It can
-- generate RSA and DSA keys, read and write PEM files, generate
-- message digests, sign and verify messages, encrypt and decrypt
-- messages.  But since OpenSSL is a very large library, it is uneasy
-- to cover everything in it.
--
-- Features that aren't (yet) supported:
--
--   [/SSL network connection/] ssl(3) functionalities aren't fully
--   covered yet. See "OpenSSL.Session".
--
--   [/Complete coverage of Low-level API to symmetric ciphers/] Only
--   high-level APIs (EVP and BIO) are fully available. But I believe
--   no one will be lost without functions like @DES_set_odd_parity@.
--
--   [/Low-level API to asymmetric ciphers/] Only a high-level API
--   (EVP) is available. But I believe no one will complain about the
--   absence of functions like @RSA_public_encrypt@.
--
--   [/Key generation of Diffie-Hellman algorithm/] Only RSA and DSA
--   keys can currently be generated.
--
--   [/X.509 v3 extension handling/] It should be supported in the
--   future.
--
--   [/Low-level API to message digest functions/] Just use EVP
--   instead of something like @MD5_Update@.
--
--   [/API to PKCS#12 functionality/] It should be covered someday.
--
--   [/BIO/] BIO isn't needed because we are Haskell hackers. Though
--   HsOpenSSL itself uses BIO internally.
--
--   [/ENGINE cryptographic module/] The default implementations work
--   very well, don't they?
--
-- So if you find out any features you want aren't supported, you must
-- write your own patch (or take over the HsOpenSSL project). Happy
-- hacking.

#include "HsOpenSSL.h"

module OpenSSL
    ( withOpenSSL
    )
    where

import OpenSSL.SSL


foreign import ccall "HsOpenSSL_setupMutex"
        setupMutex :: IO ()


-- |Computation of @'withOpenSSL' action@ initializes the OpenSSL
-- library and computes @action@. Every applications that use
-- HsOpenSSL must wrap any operations related to OpenSSL with
-- 'withOpenSSL', or they might crash.
--
-- > module Main where
-- > import OpenSSL
-- >
-- > main :: IO ()
-- > main = withOpenSSL $
-- >        do ...
--
withOpenSSL :: IO a -> IO a
withOpenSSL act
    = do loadErrorStrings
         addAllAlgorithms
         libraryInit
         setupMutex
         act
