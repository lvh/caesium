(ns caesium.crypto.secretbox
  "Bindings to the secretbox secret-key authenticated encryption scheme."
  (:require [caesium.binding :refer [sodium defconsts]]))

(defconsts [keybytes noncebytes macbytes primitive])

(defn secretbox-easy-to-buf!
  [out msg nonce key]
  (let [mlen (alength ^bytes msg)]
    (.crypto_secretbox_easy sodium out msg mlen nonce key)))

(defn secretbox-easy
  "Encrypt with `crypto_secretbox_easy`.

  Please note that this returns a (mutable!) byte array.

  This API is marginally higher level than `secretbox`: it will
  automatically prepend the required `ZERO_BYTES` NUL bytes, verify
  that the encryption succeeded, and strip them from the returned
  ciphertext."
  [msg nonce key]
  (let [out (byte-array (+ macbytes (alength ^bytes msg)))]
    (secretbox-easy-to-buf! out msg nonce key)
    out))

(defn secretbox-open-easy-to-buf!
  [out ctext nonce key]
  (let [clen (alength ^bytes ctext)
        res (.crypto_secretbox_open_easy sodium out ctext clen nonce key)]
    (if (= res 0)
      out
      (throw (RuntimeException. "Ciphertext verification failed")))))

(defn secretbox-open-easy
  "Decrypt with `crypto_secretbox_open_easy`.

  Please note that this returns a (mutable!) byte array.

  This API is marginally higher level than `secretbox_open`: it will
  automatically prepend the required `BOXZERO_BYTES` NUL bytes, verify
  that the decryption succeeded, and strip them from the returned
  plaintext."
  [ctext nonce key]
  (let [out (byte-array (- (alength ^bytes ctext) macbytes))]
    (secretbox-open-easy-to-buf! out ctext nonce key)))

(defn encrypt
  "Backwards-compatible alias for `secretbox-easy`."
  [key nonce plaintext]
  (secretbox-easy plaintext nonce key))

(defn decrypt
  "Backwards-compatible alias for `secretbox-open-easy`."
  [key nonce ciphertext]
  (secretbox-open-easy ciphertext nonce key))

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
