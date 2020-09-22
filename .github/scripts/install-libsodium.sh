#!/bin/sh -ex
LIBSODIUM_TARBALL="libsodium-${LIBSODIUM_VERSION}.tar.gz"
LIBSODIUM_TARBALL_URL="https://download.libsodium.org/libsodium/releases/${LIBSODIUM_TARBALL}"
LIBSODIUM_BUILD_DIR=libsodium-build
LIBSODIUM_BUILT_FLAG="${LIBSODIUM_BUILD_DIR}/libsodium-${LIBSODIUM_VERSION}-built"
echo "eohutnoehunto"
ls -la "${LIBSODIUM_BUILT_FLAG}" || true
echo "eouhontehuntoh"
ls -la "${LIBSODIUM_BUILD_DIR}" || true
test -f "${LIBSODIUM_BUILT_FLAG}" || (
  rm -rf "${LIBSODIUM_BUILD_DIR}"
  mkdir "${LIBSODIUM_BUILD_DIR}"
  cd "${LIBSODIUM_BUILD_DIR}"
  wget "${LIBSODIUM_TARBALL_URL}"
  wget "${LIBSODIUM_TARBALL_URL}.sig"
  gpg --import ../libsodium.pub
  gpg --verify "${LIBSODIUM_TARBALL}.sig" "${LIBSODIUM_TARBALL}"
  tar xfz "${LIBSODIUM_TARBALL}"
  cd "libsodium-${LIBSODIUM_VERSION}"
  ./configure
  make
  make check
  cd ../..
  touch "${LIBSODIUM_BUILT_FLAG}"
)
cd "${LIBSODIUM_BUILD_DIR}/libsodium-${LIBSODIUM_VERSION}"
sudo make install
