(ns caesium.crypto.secretbox
  "Bindings to the secretbox secret-key authenticated encryption scheme."
  (:require [caesium.binding :refer [sodium defconsts]])
  (:import [org.abstractj.kalium.crypto SecretBox]))

(defconsts [keybytes noncebytes macbytes primitive])

(defn encrypt
  "Encrypt with `secretbox_easy`.

  Please note that this returns a (mutable!) byte array.

  This API is marginally higher level than `secretbox`: it will
  automatically prepend the required `ZERO_BYTES` NUL bytes, verify
  that the encryption succeeded, and strip them from the returned
  ciphertext."
  [key nonce plaintext]
  (.encrypt (new SecretBox key) nonce plaintext))

(defn decrypt
  "Decrypt with `secretbox_open_easy`.

  Please note that this returns a (mutable!) byte array.

  This API is marginally higher level than `secretbox_open`: it will
  automatically prepend the required `BOXZERO_BYTES` NUL bytes, verify
  that the decryption succeeded, and strip them from the returned
  plaintext."
  [key nonce ciphertext]
  (.decrypt (new SecretBox key) nonce ciphertext))

(defn int->nonce
  "Turns an integer into a byte array, suitable as a nonce.

  The resulting byte-array is in big-endian order: it starts with the most
  significant byte. If the integer is larger than the nonce, it is
  truncated. If the integer is smaller than the nonce, it is padded with NUL
  bytes at the front.

  The return value is a mutable byte array."
  [n]
  (let [unpadded (.toByteArray (biginteger n))
        bytelen (alength unpadded)
        output (byte-array noncebytes)]
    (System/arraycopy unpadded 0 output (- noncebytes bytelen) bytelen)
    output))
