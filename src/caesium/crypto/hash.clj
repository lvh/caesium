(ns caesium.crypto.hash
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]))

(b/defconsts [sha256-bytes sha512-bytes])

(defn sha256-to-buf!
  "Hashes a message with optional key into a given output buffer using
  SHA-256.

  You only want this to manage the output byte array yourself. Otherwise, you
  want [[sha256]]."
  [buf msg]
  (b/✨ sha256 buf msg))

(defn sha256
  "Computes the SHA-256 hash of message in the given byte array.

  This is higher-level than [[sha256-to-buf!]] because you don't have to
  allocate your own output buffer."
  [msg]
  (let [buf (byte-array sha256-bytes)]
    (sha256-to-buf! (bb/->indirect-byte-buf buf) (bb/->indirect-byte-buf msg))
    buf))

(defn sha512-to-buf!
  "Hashes a message with optional key into a given output buffer using
  SHA-512.

  You only want this to manage the output byte array yourself. Otherwise, you
  want [[sha512]]."
  [buf msg]
  (b/✨ sha512 buf msg))

(defn sha512
  "Computes the SHA-512 hash of message in the given byte array.

  This is higher-level than [[sha512-to-buf!]] because you don't have to
  allocate your own output buffer."
  [msg]
  (let [buf (byte-array sha512-bytes)]
    (sha512-to-buf! (bb/->indirect-byte-buf buf) (bb/->indirect-byte-buf msg))
    buf))
