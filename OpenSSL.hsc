{- -*- haskell -*- -}

-- |HsOpenSSL is a (part of) OpenSSL binding for Haskell. It can
-- generate RSA keys, read and write PEM files, generate message
-- digests, sign and verify messages, encrypt and decrypt messages.
-- But since OpenSSL is a very large library, it is uneasy to cover
-- everything in it.
--
-- Features that aren't (yet) supported:
--
--   [/TLS\/SSL network connection/] ssl(3) functionalities are
--   totally uncovered. They should be covered someday.
--
--   [/Low-level API to symmetric ciphers/] Only high-level APIs (EVP
--   and BIO) are available. But I believe no one will be lost without
--   functions like @DES_set_odd_parity@.
--
--   [/Low-level API to asymmetric ciphers/] Only a high-level API
--   (EVP) is available. But I believe no one will complain about the
--   absence of functions like @RSA_public_encrypt@.
--
--   [/Key generation of DSA and Diffie-Hellman algorithms/] Only RSA
--   keys can currently be generated.
--
--   [/X.509 certificate handling/] No operations related to X.509 are
--   currently supported. They should be supported in the future.
--
--   [/HMAC message authentication/] 
--
--   [/Low-level API to message digest functions/] Just use EVP or BIO
--   instead of something like @MD5_Update@.
--
--   [/pseudo-random number generator/] rand(3) functionalities are
--   uncovered, but OpenSSL works very well by default.
--
--   [/API to ASN.1, PKCS\#7 and PKCS\#12 functionalities/] They
--   should be covered someday, but there seems no documents for those
--   APIs.
--
--   [/BIO/] BIO isn't needed because we are Haskell hackers.
--
--   [/ENGINE cryptographic module/] The default implementations work
--   very well, don't they?
--
--   [/bn(3), buffer(3), lhash(3), objects(3), stack(3) and txt_db(3)/]
--   These internal functions are rarely used by application
--   programmers.
--
-- So if you find out some features you want aren't supported, you
-- must write your own patch. Happy hacking.

#include "HsOpenSSL.h"

module OpenSSL
    ( -- * Initialization
      withOpenSSL

      -- * Base64
    , encodeBase64
    , encodeBase64BS
    , encodeBase64LBS
    , decodeBase64
    , decodeBase64BS
    , decodeBase64LBS

      -- * Symmetric cipher
    , EvpCipher
    , CryptoMode(..)
    , getCipherByName
    , cipher
    , cipherBS
    , cipherLBS

      -- * Message digest
    , EvpMD
    , getDigestByName
    , digest
    , digestBS
    , digestLBS

      -- * Keypair
    , EvpPKey
#ifndef OPENSSL_NO_RSA
    , newPKeyRSA
#endif

      -- * Envelope decryption
    , open
    , openBS
    , openLBS

      -- * Envelope Encryption
    , seal
    , sealBS
    , sealLBS

      -- * Signing
    , sign
    , signBS
    , signLBS

      -- * Signature verification
    , verify
    , verifyBS
    , verifyLBS

      -- * PEM routines
    , PemPasswordRWState(..)
    , PemPasswordSupply(..)
    , writePKCS8PrivateKey
    , readPrivateKey
    , writePublicKey
    , readPublicKey

      -- * RSA public key cryptosystem
    , RSA
    , generateKey
    )
    where

import OpenSSL.EVP.Base64
import OpenSSL.EVP.Cipher
import OpenSSL.EVP.Digest
import OpenSSL.EVP.Open
import OpenSSL.EVP.PKey
import OpenSSL.EVP.Seal
import OpenSSL.EVP.Sign
import OpenSSL.EVP.Verify
import OpenSSL.PEM
import OpenSSL.RSA
import OpenSSL.SSL


foreign import ccall "HsOpenSSL_setupMutex"
        setupMutex :: IO ()


-- |Computation of @'withOpenSSL' action@ initializes the OpenSSL
-- library and computes @action@. Every applications that use OpenSSL
-- must wrap any other operations related to OpenSSL or they will
-- crash.
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
         setupMutex
         act
