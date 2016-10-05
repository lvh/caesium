(ns caesium.crypto.secretbox
  "Bindings to the secretbox secret-key authenticated encryption scheme."
  (:require [caesium.binding :as b]
            [caesium.util :as u]
            [caesium.byte-bufs :as bb]
            [caesium.randombytes :as r])
  (:import [java.nio ByteBuffer]))

(b/defconsts [keybytes noncebytes macbytes primitive])

(defn secretbox-easy-to-buf!
  "Encrypt with `crypto_secretbox_easy` into the given byte buffer.

  All arguments must be `java.nio.ByteBuffer`.

  You only want this to manage the output byte buffer yourself. Otherwise,
  you want [[secretbox-easy]]."
  [c m n k]
  (b/✨ easy c m n k))

(defn secretbox-easy
  "Encrypt with `crypto_secretbox_easy`.

  Please note that this returns a (mutable!) byte array. This is a
  higher level API than [[secretbox-easy-to-buf!]] because it creates
  that output byte array for you.

  This API is marginally higher level than `secretbox`: it will
  automatically prepend the required `ZERO_BYTES` NUL bytes, verify
  that the encryption succeeded, and strip them from the returned
  ciphertext."
  [m n k]
  (let [c (bb/alloc (+ macbytes (bb/buflen m)))]
    (secretbox-easy-to-buf!
     c
     (bb/->indirect-byte-buf m)
     (bb/->indirect-byte-buf n)
     (bb/->indirect-byte-buf k))
    (bb/->bytes c)))

(defn secretbox-open-easy-to-buf!
  "Decrypt with `crypto_secretbox_open_easy` into the given byte array.

  All arguments must be `java.nio.ByteBuffer`.

  You only want this to manage the output byte array yourself. Otherwise,
  you want [[secretbox-open-easy]]."
  [m c n k]
  (let [res (b/✨ open-easy m c n k)]
    (if (zero? res)
      m
      (throw (RuntimeException. "Ciphertext verification failed")))))

(defn secretbox-open-easy
  "Decrypt with `crypto_secretbox_open_easy`.

  Please note that this returns a (mutable!) byte array. This is a
  higher level API than [[secretbox-open-easy-to-buf!]] because it
  create that output byte array for you.

  This API is marginally higher level than `secretbox_open`: it will
  automatically prepend the required `BOXZERO_BYTES` NUL bytes, verify
  that the decryption succeeded, and strip them from the returned
  plaintext."
  [c n k]
  (let [m (bb/alloc (- (bb/buflen c) macbytes))]
    (secretbox-open-easy-to-buf!
     m
     (bb/->indirect-byte-buf c)
     (bb/->indirect-byte-buf n)
     (bb/->indirect-byte-buf k))
    (bb/->bytes m)))

(defn encrypt
  "Backwards-compatible alias for [[secretbox-easy]].

  Please note that this uses a different argument order."
  [k n m]
  (secretbox-easy m n k))

(defn decrypt
  "Backwards-compatible alias for [[secretbox-open-easy]].

  Please note that this uses a different argument order."
  [k n c]
  (secretbox-open-easy c n k))

(def int->nonce
  "Turns an integer into a byte array, suitable as a nonce.

  The resulting byte-array is in big-endian order: it starts with the most
  significant byte. If the integer is larger than the nonce, it is
  truncated. If the integer is smaller than the nonce, it is padded with NUL
  bytes at the front.

  The return value is a mutable byte array."
  (partial u/n->bytes noncebytes))

(defn new-key!
  "Generates a new random key."
  []
  (r/randombytes keybytes))
