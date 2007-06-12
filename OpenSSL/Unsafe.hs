module OpenSSL.Unsafe
    ( unsafeCoercePtr
    )
    where

import           GHC.Base
import           Foreign.Ptr

unsafeCoercePtr :: Ptr a -> Ptr b
unsafeCoercePtr = unsafeCoerce#
