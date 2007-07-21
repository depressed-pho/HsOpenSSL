{- -*- haskell -*- -}

-- #hide

module OpenSSL.Stack
    ( STACK
    , mapStack
    , withStack
    , withForeignStack
    )
    where

import           Control.Exception
import           Foreign


data STACK


foreign import ccall unsafe "sk_new_null"
        skNewNull :: IO (Ptr STACK)

foreign import ccall unsafe "sk_free"
        skFree :: Ptr STACK -> IO ()

foreign import ccall unsafe "sk_push"
        skPush :: Ptr STACK -> Ptr () -> IO ()

foreign import ccall unsafe "sk_num"
        skNum :: Ptr STACK -> IO Int

foreign import ccall unsafe "sk_value"
        skValue :: Ptr STACK -> Int -> IO (Ptr ())


mapStack :: (Ptr a -> IO b) -> Ptr STACK -> IO [b]
mapStack m st
    = do num <- skNum st
         mapM (\ i -> skValue st i >>= return . castPtr >>= m)
                  $ take num [0..]


newStack :: [Ptr a] -> IO (Ptr STACK)
newStack values
    = do st <- skNewNull
         mapM_ (skPush st . castPtr) values
         return st


withStack :: [Ptr a] -> (Ptr STACK -> IO b) -> IO b
withStack values f
    = bracket (newStack values) skFree f


withForeignStack :: (fp -> Ptr obj)
                 -> (fp -> IO ())
                 -> [fp]
                 -> (Ptr STACK -> IO ret)
                 -> IO ret
withForeignStack unsafeFpToPtr touchFp fps action
    = do ret <- withStack (map unsafeFpToPtr fps) action
         mapM_ touchFp fps
         return ret
