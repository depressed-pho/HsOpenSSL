import OpenSSL
import OpenSSL.BIO as BIO

main = withOpenSSL $
       do --bMem <- new =<< s_mem
          --write bMem "Hello, world!"

          bMem <- newMemBuf "Hello, WORLD!\x0a---"
          
          cont <- BIO.gets bMem 100
          putStrLn (":" ++ cont)

          cont' <- BIO.gets bMem 100
          putStrLn (":" ++ cont')