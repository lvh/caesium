(ns caesium.crypto.hash
  (:require [caesium.binding :refer [sodium defconsts]]
            [caesium.byte-bufs :refer [buflen]]))

(defconsts [sha256-bytes sha512-bytes])

(defn sha256-to-buf!
  "Hashes a message with optional key into a given output buffer using
  SHA-256.

  You only want this to manage the output byte array yourself. Otherwise, you
  want [[sha256]]."
  [^bytes buf ^bytes msg]
  (.crypto_hash_sha256 sodium buf msg (long (buflen msg))))

(defn sha256
  "Computes the SHA-256 hash of message in the given byte array.

  This is higher-level than [[sha256-to-buf!]] because you don't have to
  allocate your own output buffer."
  [^bytes msg]
  (let [buf (byte-array sha256-bytes)]
    (sha256-to-buf! buf msg)
    buf))

(defn sha512-to-buf!
  "Hashes a message with optional key into a given output buffer using
  SHA-512.

  You only want this to manage the output byte array yourself. Otherwise, you
  want [[sha512]]."
  [^bytes buf ^bytes msg]
  (.crypto_hash_sha512 sodium buf msg (long (buflen msg))))

(defn sha512
  "Computes the SHA-512 hash of message in the given byte array.

  This is higher-level than [[sha512-to-buf!]] because you don't have to
  allocate your own output buffer."
  [^bytes msg]
  (let [buf (byte-array sha512-bytes)]
    (sha512-to-buf! buf msg)
    buf))
