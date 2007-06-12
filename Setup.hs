#!/usr/bin/env runghc

import Data.Maybe
import Distribution.PackageDescription
import Distribution.Setup
import Distribution.Simple
import Distribution.Simple.Configure
import Distribution.Simple.LocalBuildInfo
import System.IO
import System.Exit
import System.Directory
import System.Process
import Control.Monad
import Control.Exception

main = defaultMainWithHooks defaultUserHooks {preConf = preConf, postConf = postConf}
    where
      preConf :: [String] -> ConfigFlags -> IO HookedBuildInfo
      preConf args flags
          = do try (removeFile "HsOpenSSL.buildinfo")
               return emptyHookedBuildInfo
      postConf :: [String] -> ConfigFlags -> PackageDescription -> LocalBuildInfo -> IO ExitCode
      postConf args flags _ localbuildinfo
          = do biOpenSSL <- openSSLBuildInfo (configVerbose flags)
               writeHookedBuildInfo "HsOpenSSL.buildinfo" (biOpenSSL, [])
               return ExitSuccess


message :: String -> IO ()
message s = putStrLn $ "configure: " ++ s

rawSystemGrabOutput :: Int -> FilePath -> [String] -> IO String
rawSystemGrabOutput verbose path args
    = do when (verbose > 0) $
              putStrLn (path ++ concatMap (' ':) args)
         (inp,out,err,pid) <- runInteractiveProcess path args Nothing Nothing
         exitCode <- waitForProcess pid
         if exitCode /= ExitSuccess then
             do errMsg <- hGetContents err
                hPutStr stderr errMsg
                exitWith exitCode else
             return ()
         hClose inp
         hClose err
         hGetContents out

mergeBuildInfo :: BuildInfo -> BuildInfo -> BuildInfo
mergeBuildInfo b1 b2 = BuildInfo {
                         buildable    = buildable    b1 || buildable    b2,
                         ccOptions    = ccOptions    b1 ++ ccOptions    b2,
                         ldOptions    = ldOptions    b1 ++ ldOptions    b2,
                         frameworks   = frameworks   b1 ++ frameworks   b2,
                         cSources     = cSources     b1 ++ cSources     b2,
                         hsSourceDirs = hsSourceDirs b1 ++ hsSourceDirs b2,
                         otherModules = otherModules b1 ++ otherModules b2,
                         extensions   = extensions   b1 ++ extensions   b2,
                         extraLibs    = extraLibs    b1 ++ extraLibs    b2,
                         extraLibDirs = extraLibDirs b1 ++ extraLibDirs b2,
                         includeDirs  = includeDirs  b1 ++ includeDirs  b2,
                         includes     = includes     b1 ++ includes     b2,
                         installIncludes = installIncludes b1 ++ installIncludes b2,
                         options      = options      b1 ++ options      b2,
                         ghcProfOptions = ghcProfOptions b1 ++ ghcProfOptions b2
                       }

openSSLBuildInfo :: Int -> IO (Maybe BuildInfo)
openSSLBuildInfo verbose
    = do Just pkg_config_path <- findProgram "pkg-config" Nothing
         message "configuring OpenSSL library"
         res <- rawSystemGrabOutput verbose pkg_config_path ["--libs", "openssl"]
         let (lib_dirs, libs, ld_opts) = splitLibsFlags (words res)
         res <- rawSystemGrabOutput verbose pkg_config_path ["--cflags", "openssl"]
         let (inc_dirs, cc_opts) = splitCFlags (words res)
         let bi = emptyBuildInfo {
                    extraLibDirs = lib_dirs
                  , extraLibs    = libs
                  , ldOptions    = ld_opts
                  , includeDirs  = inc_dirs
                  , ccOptions    = cc_opts
                  }
         return $ Just bi


splitLibsFlags :: [String] -> ([String], [String], [String])
splitLibsFlags []         = ([], [], [])
splitLibsFlags (arg:args)
    = case arg
      of ('-':'L':lib_dir) -> let (lib_dirs, libs, ld_opts) = splitLibsFlags args
                              in  (lib_dir:lib_dirs, libs, ld_opts)
         ('-':'l':lib)     -> let (lib_dirs, libs, ld_opts) = splitLibsFlags args
                              in  (lib_dirs, lib:libs, ld_opts)
         ld_opt            -> let (lib_dirs, libs, ld_opts) = splitLibsFlags args
                              in  (lib_dirs, libs, ld_opt:ld_opts)

splitCFlags :: [String] -> ([String], [String])
splitCFlags []         = ([], [])
splitCFlags (arg:args)
    = case arg
      of ('-':'I':inc_dir) -> let (inc_dirs, c_opts) = splitCFlags args
                              in  (inc_dir:inc_dirs, c_opts)
         c_opt             -> let (inc_dirs, c_opts) = splitCFlags args
                              in  (inc_dirs, c_opt:c_opts)
