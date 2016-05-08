(ns caesium.crypto.secretbox
  "Bindings to the secretbox secret-key authenticated encryption scheme."
  (:require [caesium.binding :refer [sodium defconsts]]
            [caesium.crypto.generichash :as g]
            [caesium.util :as u])
  (:import [java.util Arrays]))

(defconsts [keybytes noncebytes macbytes primitive])

(defn secretbox-easy-to-buf!
  "Encrypt with `crypto_secretbox_easy` into the given byte array.

  You only want this to manage the output byte array yourself. Otherwise,
  you want [[secretbox-easy]]."
  [out msg nonce key]
  (let [mlen (alength ^bytes msg)]
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
  "Encrypt with `crypto_secretbox_open_easy` into the given byte array.

  You only want this to manage the output byte array yourself. Otherwise,
  you want [[secretbox-open-easy]]."
  [out ctext nonce key]
  (let [clen (alength ^bytes ctext)
        res (.crypto_secretbox_open_easy sodium out ctext clen nonce key)]
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

(def ^:private autononce-personal
  (.getBytes "secretbox nonce "))

(assert (count autononce-personal) g/blake2b-personalbytes)

(defn ^:private autononce
  [key msg]
  (g/blake2b msg {:size noncebytes :key key :personal autononce-personal}))

(defn ^:private encrypt-autononce
  [key msg]
  (let [clen (+ (alength ^bytes msg) macbytes)
        tlen (+ clen noncebytes)
        out (byte-array tlen)
        nonce (autononce key msg)]
    (secretbox-easy-to-buf! out msg nonce key)
    (System/arraycopy nonce 0 out clen noncebytes)
    out))

(defn ^:private decrypt-autononce
  [key ^bytes ctext]
  (let [tlen (alength ctext)
        clen (- tlen noncebytes)
        nonce (Arrays/copyOfRange ctext ^int clen (inc tlen))
        truncated-ctext (Arrays/copyOf ctext ^int clen)]
    (decrypt key nonce truncated-ctext)))

(defn ^:private autononce-test
  []
  (let [k (byte-array keybytes)]
    (->> (byte-array 10)
         (encrypt-autononce k)
         (decrypt-autononce k))))
