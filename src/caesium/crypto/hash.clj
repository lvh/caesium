(ns caesium.crypto.hash
  (:require [caesium.binding :refer [sodium defconsts]]))

(defconsts [sha256-bytes sha512-bytes])

(defn sha256-to-buf!
  [buf msg]
  (.crypto_hash_sha256 sodium buf msg (alength ^bytes msg)))

(defn sha256
  [msg]
  (let [buf (byte-array sha256-bytes)]
    (sha256-to-buf! buf msg)
    buf))

(defn sha512-to-buf!
  [buf msg]
  (.crypto_hash_sha512 sodium buf msg (alength ^bytes msg)))

(defn sha512
  [msg]
  (let [buf (byte-array sha512-bytes)]
    (sha512-to-buf! buf msg)
    buf))
