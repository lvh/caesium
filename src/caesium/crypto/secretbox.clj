(ns caesium.crypto.secretbox
  "Bindings to the secretbox secret-key authenticated encryption scheme."
  (:require [caesium.binding :refer [sodium defconsts]]
            [caesium.util :as u]
            [caesium.bytes-conv :as bc])
  (:import [java.nio ByteBuffer]))

(defconsts [keybytes noncebytes macbytes primitive])

(defn secretbox-easy-to-direct-byte-bufs-with-macros!
  "Encrypt with `crypto_secretbox_easy`.

  All arguments will be converted to byte buffers. If this involves
  allocating a new byte buffer, that byte buffer will be allocated as
  a direct byte buffer. This is the case whenever an argument is not a
  byte buffer already; including when it is a byte array. You only
  want this to manage the output byte buffers yourself. Otherwise, you
  want [[secretbox-easy]]. "
  [out msg nonce key]
  (let [^ByteBuffer out (bc/->direct-byte-buf-macro out)
        ^ByteBuffer msg (bc/->direct-byte-buf-macro msg)
        ^ByteBuffer nonce (bc/->direct-byte-buf-macro nonce)
        ^ByteBuffer key (bc/->direct-byte-buf-macro key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-direct-byte-bufs!
  "Encrypt with `crypto_secretbox_easy`.

  All arguments will be converted to byte buffers. If this involves
  allocating a new byte buffer, that byte buffer will be allocated as
  a direct byte buffer. This is the case whenever an argument is not a
  byte buffer already; including when it is a byte array. You only
  want this to manage the output byte buffers yourself. Otherwise, you
  want [[secretbox-easy]]. "
  [out msg nonce key]
  (let [^ByteBuffer out (bc/->direct-byte-buf out)
        ^ByteBuffer msg (bc/->direct-byte-buf msg)
        ^ByteBuffer nonce (bc/->direct-byte-buf nonce)
        ^ByteBuffer key (bc/->direct-byte-buf key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-indirect-byte-bufs-with-macros!
  "Encrypt with `crypto_secretbox_easy`.

  All arguments will be converted to byte buffers. If this involves
  allocating a new byte buffer, that byte buffer will be allocated as
  an indirect byte buffer. This is the case whenever an argument is not a
  byte buffer already; including when it is a byte array. You only
  want this to manage the output byte buffers yourself. Otherwise, you
  want [[secretbox-easy]]. "
  [out msg nonce key]
  (let [^ByteBuffer out (bc/->indirect-byte-buf-macro out)
        ^ByteBuffer msg (bc/->indirect-byte-buf-macro msg)
        ^ByteBuffer nonce (bc/->indirect-byte-buf-macro nonce)
        ^ByteBuffer key (bc/->indirect-byte-buf-macro key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-indirect-byte-bufs!
  "Encrypt with `crypto_secretbox_easy`.

  All arguments will be converted to byte buffers. If this involves
  allocating a new byte buffer, that byte buffer will be allocated as
  an indirect byte buffer. This is the case whenever an argument is not a
  byte buffer already; including when it is a byte array. You only
  want this to manage the output byte buffers yourself. Otherwise, you
  want [[secretbox-easy]]. "
  [out msg nonce key]
  (let [^ByteBuffer out (bc/->indirect-byte-buf out)
        ^ByteBuffer msg (bc/->indirect-byte-buf msg)
        ^ByteBuffer nonce (bc/->indirect-byte-buf nonce)
        ^ByteBuffer key (bc/->indirect-byte-buf key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-byte-bufs-nocast!
  [^ByteBuffer out ^ByteBuffer msg ^ByteBuffer nonce ^ByteBuffer key]
  (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
  out)

(defn secretbox-easy-to-buf!
  "Encrypt with `crypto_secretbox_easy` into the given byte array.

  You only want this to manage the output byte array yourself. Otherwise,
  you want [[secretbox-easy]]."
  [^bytes out ^bytes msg ^bytes nonce ^bytes key]
  (let [mlen (long (alength ^bytes msg))]
    (.crypto_secretbox_easy sodium out msg mlen nonce key)))

(defn secretbox-easy-to-byte-buf!
  "Like [[secretbox-easy-to-buf!]], but with a ByteBuffer output.

  Like [[secretbox-easy-to-buf!]], this is only useful if you want to manage
  the output byte buffer yourself. Otherwise, you want [[secretbox-easy]]."
  [^java.nio.ByteBuffer out ^bytes msg ^bytes nonce ^bytes key]
  (let [mlen (long (alength ^bytes msg))]
    (.crypto_secretbox_easy sodium out msg mlen nonce key)))

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
  (let [out (byte-array (+ macbytes (alength ^bytes msg)))]
    (secretbox-easy-to-buf! out msg nonce key)
    out))

(defn secretbox-open-easy-to-buf!
  "Decrypt with `crypto_secretbox_open_easy` into the given byte array.

  You only want this to manage the output byte array yourself. Otherwise,
  you want [[secretbox-open-easy]]."
  [^bytes out ^bytes ctext ^bytes nonce ^bytes key]
  (let [clen (alength ctext)
        res (.crypto_secretbox_open_easy sodium out ctext clen nonce key)]
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
  (let [res (.crypto_secretbox_open_easy sodium
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
  (let [out (byte-array (- (alength ^bytes ctext) macbytes))]
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
