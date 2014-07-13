{- -*- haskell -*- -}

-- |An interface to symmetric cipher algorithms.

#include "HsOpenSSL.h"

module OpenSSL.EVP.Cipher
    ( Cipher
    , getCipherByName
    , getCipherNames

    , CryptoMode(..)

    , cipherInit
    , cipher
    , cipherBS
    , cipherLBS
    , cipherStrictLBS
    )
    where
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import Foreign
import Foreign.C
import OpenSSL.Objects
import OpenSSL.Utils
import OpenSSL.EVP.Internal

foreign import ccall unsafe "EVP_get_cipherbyname"
        _get_cipherbyname :: CString -> IO (Ptr EVP_CIPHER)

-- |@'getCipherByName' name@ returns a symmetric cipher algorithm
-- whose name is @name@. If no algorithms are found, the result is
-- @Nothing@.
getCipherByName :: String -> IO (Maybe Cipher)
getCipherByName name
    = withCString name $ \ namePtr ->
      do ptr <- _get_cipherbyname namePtr
         if ptr == nullPtr then
             return Nothing
           else
             return $ Just $ Cipher ptr

-- |@'getCipherNames'@ returns a list of name of symmetric cipher
-- algorithms.
getCipherNames :: IO [String]
getCipherNames = getObjNames CipherMethodType True

{- encrypt/decrypt ----------------------------------------------------------- -}

-- |@CryptoMode@ represents instruction to 'cipher' and such like.
data CryptoMode = Encrypt | Decrypt

cryptoModeToInt :: CryptoMode -> CInt
cryptoModeToInt Encrypt = 1
cryptoModeToInt Decrypt = 0

foreign import ccall unsafe "EVP_CipherInit"
        _CipherInit :: Ptr EVP_CIPHER_CTX -> Ptr EVP_CIPHER -> CString -> CString -> CInt -> IO CInt

cipherInit :: Cipher -> String -> String -> CryptoMode -> IO CipherCtx
cipherInit (Cipher c) key iv mode
    = do ctx <- newCipherCtx
         withCipherCtxPtr ctx $ \ ctxPtr ->
             withCString key $ \ keyPtr ->
                 withCString iv $ \ ivPtr ->
                     _CipherInit ctxPtr c keyPtr ivPtr (cryptoModeToInt mode)
                          >>= failIf_ (/= 1)
         return ctx

-- | Encrypt a lazy bytestring in a strict manner. Does not leak the keys.
cipherStrictLBS :: Cipher         -- ^ Cipher
                -> B8.ByteString  -- ^ Key
                -> B8.ByteString  -- ^ IV
                -> CryptoMode     -- ^ Encrypt\/Decrypt
                -> L8.ByteString  -- ^ Input
                -> IO L8.ByteString
cipherStrictLBS (Cipher c) key iv mode input =
  withNewCipherCtxPtr $ \cptr ->
  unsafeUseAsCStringLen key $ \(keyp,_) ->
  unsafeUseAsCStringLen iv  $ \(ivp, _) -> do
  failIf_ (/= 1) =<< _CipherInit cptr c keyp ivp (cryptoModeToInt mode)
  cc <- fmap CipherCtx (newForeignPtr_ cptr)
  rr <- cipherUpdateBS cc `mapM` L8.toChunks input
  rf <- cipherFinalBS cc
  return $ L8.fromChunks (rr++[rf])

-- |@'cipher'@ lazilly encrypts or decrypts a stream of data. The
-- input string doesn't necessarily have to be finite.
cipher :: Cipher     -- ^ algorithm to use
       -> String     -- ^ symmetric key
       -> String     -- ^ IV
       -> CryptoMode -- ^ operation
       -> String     -- ^ An input string to encrypt\/decrypt. Note
                     --   that the string must not contain any letters
                     --   which aren't in the range of U+0000 -
                     --   U+00FF.
       -> IO String  -- ^ the result string
cipher c key iv mode input
    = fmap L8.unpack $ cipherLBS c key iv mode $ L8.pack input

-- |@'cipherBS'@ strictly encrypts or decrypts a chunk of data.
cipherBS :: Cipher        -- ^ algorithm to use
         -> String        -- ^ symmetric key
         -> String        -- ^ IV
         -> CryptoMode    -- ^ operation
         -> B8.ByteString    -- ^ input string to encrypt\/decrypt
         -> IO B8.ByteString -- ^ the result string
cipherBS c key iv mode input
    = do ctx <- cipherInit c key iv mode
         cipherStrictly ctx input

-- |@'cipherLBS'@ lazilly encrypts or decrypts a stream of data. The
-- input string doesn't necessarily have to be finite.
cipherLBS :: Cipher            -- ^ algorithm to use
          -> String            -- ^ symmetric key
          -> String            -- ^ IV
          -> CryptoMode        -- ^ operation
          -> L8.ByteString    -- ^ input string to encrypt\/decrypt
          -> IO L8.ByteString -- ^ the result string
cipherLBS c key iv mode input
    = do ctx <- cipherInit c key iv mode
         cipherLazily ctx input

