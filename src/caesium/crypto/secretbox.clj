(ns caesium.crypto.secretbox
  "Bindings to the secretbox secret-key authenticated encryption scheme."
  (:require [caesium.binding :as b]
            [caesium.util :as u]
            [caesium.byte-bufs :refer [buflen]])
  (:import [java.nio ByteBuffer]))

(b/defconsts [keybytes noncebytes macbytes primitive])

(defn secretbox-easy-to-buf!
  "Encrypt with `crypto_secretbox_easy` into the given byte buffer.

  All arguments must be `java.nio.ByteBuffer`.

  You only want this to manage the output byte buffer yourself. Otherwise,
  you want [[secretbox-easy]]."
  [c m n k]
  (b/✨ easy m n k))

(defn secretbox-easy
  "Encrypt with `crypto_secretbox_easy`.

  Please note that this returns a (mutable!) byte array. This is a
  higher level API than [[secretbox-easy-to-buf!]] because it create
  that output byte array for you.

  This API is marginally higher level than `secretbox`: it will
  automatically prepend the required `ZERO_BYTES` NUL bytes, verify
  that the encryption succeeded, and strip them from the returned
  ciphertext."
  [msg nonce key]
  (let [out (byte-array (+ macbytes (buflen msg)))]
    (secretbox-easy-to-buf! out msg nonce key)
    out))

(defn secretbox-open-easy-to-buf!
  "Decrypt with `crypto_secretbox_open_easy` into the given byte array.

  You only want this to manage the output byte array yourself. Otherwise,
  you want [[secretbox-open-easy]]."
  [^bytes out ^bytes ctext ^bytes nonce ^bytes key]
  (let [clen (long (buflen ctext))
        res (.crypto_secretbox_open_easy b/sodium out ctext clen nonce key)]
    (if (= res 0)
      out
      (throw (RuntimeException. "Ciphertext verification failed")))))

(defn secretbox-open-easy-from-byte-bufs!
  "**WARNING** low-level API, specialized use!

  This function is probably only useful if you're using ByteBuffers to manage
  the layout of a byte array that contains both the nonce and the
  secretbox-easy ciphertext. If you're not sure, this is not the API you want;
  check out [[secretbox-open-easy]] instead."
  [out ctext ctextlen nonce key]
  ;; This takes an ctextlen argument because you can't tell the appropriate
  ;; length from the ctext ByteBuffer and the caller knows anyway.
  (let [res (.crypto_secretbox_open_easy b/sodium
                                         ^bytes out
                                         ^java.nio.ByteBuffer ctext
                                         ^long ctextlen
                                         ^java.nio.ByteBuffer nonce
                                         ^bytes key)]
    (if (= res 0)
      out
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
  [ctext nonce key]
  (let [out (byte-array (- (buflen ctext) macbytes))]
    (secretbox-open-easy-to-buf! out ctext nonce key)))

(defn encrypt
  "Backwards-compatible alias for [[secretbox-easy]].

  Please note that this uses a different argument order."
  [key nonce msg]
  (secretbox-easy msg nonce key))

(defn decrypt
  "Backwards-compatible alias for [[secretbox-open-easy]].

  Please note that this uses a different argument order."
  [key nonce ciphertext]
  (secretbox-open-easy ciphertext nonce key))

(def int->nonce
  "Turns an integer into a byte array, suitable as a nonce.

  The resulting byte-array is in big-endian order: it starts with the most
  significant byte. If the integer is larger than the nonce, it is
  truncated. If the integer is smaller than the nonce, it is padded with NUL
  bytes at the front.

  The return value is a mutable byte array."
  (partial u/n->bytes noncebytes))
