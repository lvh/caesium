(ns caesium.crypto.hash
  (:require [caesium.binding :refer [sodium]]))

(def ^:private sha256-bytes
  (.crypto_hash_sha256_bytes sodium))

(defn sha256
  "Computes the SHA-256 digest of the given message with `crypto_hash_sha256`."
  [^bytes msg]
  (let [buf (byte-array sha256-bytes)]
    (.crypto_hash_sha256 sodium buf msg (alength msg))
    buf))

(def ^:private sha512-bytes
  (.crypto_hash_sha512_bytes sodium))

(defn sha512
  "Computes the SHA-512 digest of the given message with `crypto_hash_sha512`."
  [^bytes msg]
  (let [buf (byte-array sha512-bytes)]
    (.crypto_hash_sha512 sodium buf msg (alength msg))
    buf))
