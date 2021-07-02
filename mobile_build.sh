#!/bin/bash
#
# Script to build libraries for tari_crypto
#

#Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

source mobile_build.config
REPO_PATH=${REPO_PATH:-$(git rev-parse --show-toplevel)}
CURRENT_DIR=${REPO_PATH}
cd ${CURRENT_DIR} || exit
mkdir -p logs
cd logs || exit
mkdir -p ios
mkdir -p android
IOS_LOG_PATH=${CURRENT_DIR}/logs/ios
ANDROID_LOG_PATH=${CURRENT_DIR}/logs/android
cd ..

unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*)    MACHINE=Cygwin;;
    MINGW*)     MACHINE=MinGw;;
    *)          MACHINE="UNKNOWN:${unameOut}"
esac
export PKG_CONFIG_ALLOW_CROSS=1

# Fix for macOS Catalina failing to include correct headers for cross compilation
if [ "${MACHINE}" == "Mac" ]; then
  MAC_VERSION=$(sw_vers -productVersion)
  MAC_MAIN_VERSION=$(cut -d '.' -f1 <<<"$(sw_vers -productVersion)")
  MAC_SUB_VERSION=$(cut -d '.' -f2 <<<"$(sw_vers -productVersion)")
  echo "${PURPLE}Mac version as reported by OS: ${MAC_VERSION}"
  if [ "${MAC_MAIN_VERSION}" -le 10 ]; then
    if [ "${MAC_SUB_VERSION}" -ge 15 ]; then
      unset CPATH
      echo "${PURPLE}macOS 10.15 Detected${NC}"
    else
      echo "${PURPLE}macOS 10.14- Detected${NC}"
    fi
  else
    unset CPATH
    echo "${PURPLE}macOS 11+ Detected${NC}"
  fi
fi

# IOS BUILD
# BUILD_IOS is defined in mobile_build.config
# shellcheck disable=SC2153
if [ "${BUILD_IOS}" -eq 1 ] && [ "${MACHINE}" == "Mac" ]; then
  echo "${GREEN}Commencing iOS build${NC}"
  echo "${YELLOW}Build logs can be found at ${IOS_LOG_PATH}${NC}"
  echo "\t${CYAN}Configuring Rust${NC}"
  rustup target add aarch64-apple-ios x86_64-apple-ios >> ${IOS_LOG_PATH}/rust.txt 2>&1
  cargo install cargo-lipo >> ${IOS_LOG_PATH}/rust.txt 2>&1
  echo "\t${CYAN}Configuring complete${NC}"

  mkdir -p mobile_build
  cd mobile_build || exit
  mkdir -p ios
  cd ios || exit
  BUILD_ROOT=$PWD
  cd ${CURRENT_DIR} || exit
  if [ "${CARGO_CLEAN}" -eq "1" ]; then
      cargo clean >> ${IOS_LOG_PATH}/cargo.txt 2>&1
  fi
  export PKG_CONFIG_PATH=${PKG_PATH}
  echo "\t${CYAN}Building Tari Crypto FFI${NC}"
  cargo-lipo lipo --features=ffi --release > ${IOS_LOG_PATH}/cargo.txt 2>&1
  cd target || exit
  cd universal || exit
  cd release || exit
  cp libtari_crypto.a "${BUILD_ROOT}"
  cd ../../.. || exit
  rm -rf target
  echo "${GREEN}iOS build completed${NC}"
elif [ "${BUILD_IOS}" -eq 1 ]; then
  echo "${RED}Cannot configure iOS Crypto Library build${NC}"
else
  echo "${GREEN}iOS Crypto is configured not to build${NC}"
fi

# ANDROID BUILD
# BUILD_ANDROID, NDK_PATH is defined in mobile_build.config
# shellcheck disable=SC2153
if [ -n "${NDK_PATH}" ] && [ "${BUILD_ANDROID}" -eq 1 ]; then
  echo "${GREEN}Commencing Android build${NC}"
  echo "${YELLOW}Build logs can be found at ${ANDROID_LOG_PATH}${NC}"
  echo "\t${CYAN}Configuring Rust${NC}"
  rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi i686-linux-android arm-linux-androideabi > ${ANDROID_LOG_PATH}/rust.txt 2>&1
  if [ "${MAC_MAIN_VERSION}" -le 10 ]; then
    if [ "${MAC_SUB_VERSION}" -lt 15 ]; then
      cargo install cargo-ndk >> ${ANDROID_LOG_PATH}/rust.txt 2>&1
    fi
  fi
  echo "\t${CYAN}Configuring complete${NC}"
  export NDK_HOME=${NDK_PATH}
  export NDK_TOOLCHAIN_VERSION=clang

  mkdir -p mobile_build
  cd mobile_build || exit
  mkdir -p android
  cd android || exit
  BUILD_ROOT=${PWD}
  if [ "${MACHINE}" == "Mac" ]; then
    if [ "${MAC_MAIN_VERSION}" -le 10 ]; then
      if [ "${MAC_SUB_VERSION}" -ge 15 ]; then
        cd ${NDK_HOME}/sources/cxx-stl/llvm-libc++/include || exit
        mkdir -p sys
        #Fix for missing header, c code should reference limits.h instead of syslimits.h, happens with code that has been around for a long time.
        cp "${NDK_HOME}/sources/cxx-stl/llvm-libc++/include/limits.h" "${NDK_HOME}/sources/cxx-stl/llvm-libc++/include/sys/syslimits.h"
        cd ${BUILD_ROOT} || exit
      fi
      else
        cd ${NDK_HOME}/sources/cxx-stl/llvm-libc++/include || exit
        mkdir -p sys
        cp "${NDK_HOME}/sources/cxx-stl/llvm-libc++/include/limits.h" "${NDK_HOME}/sources/cxx-stl/llvm-libc++/include/sys/syslimits.h"
        cd ${BUILD_ROOT} || exit
    fi
  fi
  cd ..

  for PLATFORMABI in "i686-linux-android" "x86_64-linux-android" "aarch64-linux-android" "armv7-linux-androideabi"
  do
    # Lint warning for loop only running once is acceptable here
    # shellcheck disable=SC2043
    for LEVEL in 24
    #21 22 23 26 26 27 28 29 not included at present
    do
      touch ${ANDROID_LOG_PATH}/cargo_${PLATFORMABI}_${LEVEL}.txt

      PLATFORM=$(cut -d'-' -f1 <<<"${PLATFORMABI}")

      PLATFORM_OUTDIR=""
      if [ "${PLATFORM}" == "i686" ]; then
        PLATFORM_OUTDIR="x86"
        elif [ "${PLATFORM}" == "x86_64" ]; then
          PLATFORM_OUTDIR="x86_64"
        elif [ "${PLATFORM}" == "armv7" ]; then
          PLATFORM_OUTDIR="armeabi-v7a"
        elif [ "${PLATFORM}" == "aarch64" ]; then
          PLATFORM_OUTDIR="arm64-v8a"
        else
          PLATFORM_OUTDIR=${PLATFORM}
      fi
      cd ${BUILD_ROOT} || exit
      mkdir -p ${PLATFORM_OUTDIR}
      OUTPUT_DIR=${BUILD_ROOT}/${PLATFORM_OUTDIR}

      PLATFORMABI_TOOLCHAIN=${PLATFORMABI}
      PLATFORMABI_COMPILER=${PLATFORMABI}
      if [ "${PLATFORMABI}" == "armv7-linux-androideabi" ]; then
        PLATFORMABI_TOOLCHAIN="arm-linux-androideabi"
        PLATFORMABI_COMPILER="armv7a-linux-androideabi"
      fi
      # set toolchain path
      TOOLCHAIN_PATH=${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/
      export TOOLCHAIN=${TOOLCHAIN_PATH}${PLATFORMABI_TOOLCHAIN}

      # undo compiler configuration (if set) of previous iteration
      unset AR;
      unset AS;
      unset CC;
      unset CXX;
      unset CXXFLAGS;
      unset LD;
      unset LDFLAGS;
      unset RANLIB;
      unset STRIP;
      unset CFLAGS;
      unset CXXFLAGS;

      # set the archiver
      export AR=${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${PLATFORMABI_TOOLCHAIN}$'-'ar

      # set the assembler
      export AS=${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${PLATFORMABI_TOOLCHAIN}$'-'as

      # set the c and c++ compiler
      CC=${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${PLATFORMABI_COMPILER}
      export CC=${CC}${LEVEL}$'-'clang
      export CXX=${CC}++

      export CXXFLAGS="-stdlib=libstdc++ -isystem ${NDK_HOME}/sources/cxx-stl/llvm-libc++/include"
      # set the linker
      export LD=${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${PLATFORMABI_TOOLCHAIN}$'-'ld

      # set linker flags
      export LDFLAGS="-L${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/lib/${PLATFORMABI_TOOLCHAIN}/${LEVEL} -L${OUTPUT_DIR}/lib -lc++"

      # set the archive index generator tool
      export RANLIB=${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${PLATFORMABI_TOOLCHAIN}$'-'ranlib

      # set the symbol stripping tool
      export STRIP=${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${PLATFORMABI_TOOLCHAIN}$'-'strip

      # set c flags
      #note: Add -v to below to see compiler output, include paths, etc
      export CFLAGS=""

      # set cpp flags
      export CPPFLAGS="-fPIC -I${OUTPUT_DIR}/include"

      if [ "${MACHINE}" == "Mac" ]; then
        if [ "${MAC_MAIN_VERSION}" -le 10 ]; then
          if [ "${MAC_SUB_VERSION}" -ge 15 ]; then
            # Not ideal, however necesary for cargo to pass additional flags
            export CFLAGS="${CFLAGS} -I${NDK_HOME}/sources/cxx-stl/llvm-libc++/include -I${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/include -I${NDK_HOME}/sysroot/usr/include/${PLATFORMABI}"
          fi
        else
            export CFLAGS="${CFLAGS} -I${NDK_HOME}/sources/cxx-stl/llvm-libc++/include -I${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/include -I${NDK_HOME}/sysroot/usr/include/${PLATFORMABI}"
        fi
      fi
      export LDFLAGS="-L${NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/lib/${PLATFORMABI_TOOLCHAIN}/${LEVEL} -L${OUTPUT_DIR}/lib -L${OUTPUT_DIR}/usr/local/lib -lc++"

      echo "\t${CYAN}Configuring Cargo${NC}"
      cd ${CURRENT_DIR} || exit
      if [ "${CARGO_CLEAN}" -eq "1" ]; then
        cargo clean >> ${ANDROID_LOG_PATH}/cargo_${PLATFORMABI}_${LEVEL}.txt 2>&1
      fi
      mkdir -p .cargo
      cd .cargo || exit
      if [ "${MACHINE}" == "Mac" ]; then
        if [ "${MAC_MAIN_VERSION}" -le 10 ]; then
          if [ "${MAC_SUB_VERSION}" -ge 15 ]; then
cat > config <<EOF
[build]
target = "${PLATFORMABI}"

[target.${PLATFORMABI}]
ar = "${AR}"
linker = "${CC}"
rustflags = "-L${OUTPUT_DIR}/lib -L${OUTPUT_DIR}/usr/local/lib"

EOF

        else
cat > config <<EOF
[target.${PLATFORMABI}]
ar = "${AR}"
linker = "${CC}"
rustflags = "-L${OUTPUT_DIR}/lib -L${OUTPUT_DIR}/usr/local/lib"

EOF

        fi
        else
cat > config <<EOF
[build]
target = "${PLATFORMABI}"

[target.${PLATFORMABI}]
ar = "${AR}"
linker = "${CC}"
rustflags = "-L${OUTPUT_DIR}/lib -L${OUTPUT_DIR}/usr/local/lib"

EOF

          fi
      fi
      echo "\t${CYAN}Configuring complete${NC}"
      cd .. || exit
      echo "\t${CYAN}Building Tari Crypto FFI${NC}"
      #note: add -vv to below to see verbose and build script output
      if [ "${MACHINE}" == "Mac" ]; then
        if [ "${MAC_MAIN_VERSION}" -le 10 ]; then
          if [ "${MAC_SUB_VERSION}" -ge 15 ]; then
            cargo build --lib --release --features=ffi >> ${ANDROID_LOG_PATH}/cargo_${PLATFORMABI}_${LEVEL}.txt 2>&1
          else
            cargo ndk --target ${PLATFORMABI} --android-platform ${LEVEL} -- build --release --features=ffi >> ${ANDROID_LOG_PATH}/cargo_${PLATFORMABI}_${LEVEL}.txt 2>&1
          fi
        else
          cargo build --lib --release --features=ffi >> ${ANDROID_LOG_PATH}/cargo_${PLATFORMABI}_${LEVEL}.txt 2>&1
        fi
      else
        cargo ndk --target ${PLATFORMABI} --android-platform ${LEVEL} -- build --release --features=ffi >> ${ANDROID_LOG_PATH}/cargo_${PLATFORMABI}_${LEVEL}.txt 2>&1
      fi
      rm -rf .cargo
      cd target || exit
      cd ${PLATFORMABI} || exit
      cd release || exit
      cp libtari_crypto.a ${OUTPUT_DIR}
      cd ../../..
      rm -rf target
      echo "\t${GREEN}Crypto library built for android architecture ${PLATFORM_OUTDIR} with minimum platform level support of ${LEVEL}${NC}"
    done
  done
  echo "${GREEN}Android build completed${NC}"
elif [ ${BUILD_ANDROID} -eq 1 ]; then
  echo "${RED}Cannot configure Android Crypto Library build${NC}"
else
  echo "${GREEN}Android Crypto is configured not to build${NC}"
fi
