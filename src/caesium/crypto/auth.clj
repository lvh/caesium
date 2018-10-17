(ns caesium.crypto.auth
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]))

(b/defconsts [hmacsha256-bytes hmacsha256-keybytes
              hmacsha512-bytes hmacsha512-keybytes
              hmacsha512256-bytes hmacsha512256-keybytes])

(defn hmacsha256-to-buf!
  "Computes an authentication tag for a message into a given output buffer using
  SHA-256 and a 256-bit key.

  You only want this to manage the output byte array yourself. Otherwise, you
  want [[hmacsha256]]."
  [buf msg k]
  (b/call! hmacsha256 buf msg k))

(defn hmacsha256
  "Computes an authentication tag for a message using SHA-256 and a 256-bit key.

  This is higher-level than [[hmacsha256-to-buf!]] because you don't have to
  allocate your own output buffer."
  [msg k]
  (let [buf (byte-array hmacsha256-bytes)]
    (hmacsha256-to-buf! (bb/->indirect-byte-buf buf) (bb/->indirect-byte-buf msg) (bb/->indirect-byte-buf k))
    buf))

(defn hmacsha512-to-buf!
  "Computes an authentication tag for a message into a given output buffer using
  SHA-512 and a 256-bit key.

  You only want this to manage the output byte array yourself. Otherwise, you
  want [[hmacsha512]]."
  [buf msg k]
  (b/call! hmacsha512 buf msg k))

(defn hmacsha512
  "Computes an authentication tag for a message using SHA-512 and a 256-bit key.

  This is higher-level than [[hmacsha512-to-buf!]] because you don't have to
  allocate your own output buffer."
  [msg k]
  (let [buf (byte-array hmacsha512-bytes)]
    (hmacsha512-to-buf! (bb/->indirect-byte-buf buf) (bb/->indirect-byte-buf msg) (bb/->indirect-byte-buf k))
    buf))

(defn hmacsha512256-to-buf!
  "Computes an authentication tag for a message into a given output buffer using
  SHA-512 and a 256-bit key, and then truncates the resulting tag to 256 bits.

  You only want this to manage the output byte array yourself. Otherwise, you
  want [[hmacsha512256]]."
  [buf msg k]
  (b/call! hmacsha512256 buf msg k))

(defn hmacsha512256
  "Computes an authentication tag for a message using SHA-512 and a 256-bit key,
  and then truncates the resulting tag to 256 bits.

  This is higher-level than [[hmacsha512256-to-buf!]] because you don't have to
  allocate your own output buffer."
  [msg k]
  (let [buf (byte-array hmacsha512256-bytes)]
    (hmacsha512256-to-buf! (bb/->indirect-byte-buf buf) (bb/->indirect-byte-buf msg) (bb/->indirect-byte-buf k))
    buf))

