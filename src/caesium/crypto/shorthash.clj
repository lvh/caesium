(ns caesium.crypto.shorthash
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]
            [caesium.util :as u]))

(b/defconsts [bytes
              keybytes
              primitive])

(defn keygen-to-buf! [k]
  (b/call! keygen k))

(defn keygen! []
  (let [k (bb/alloc keybytes)]
    (keygen-to-buf! k)
    k))

(defn shorthash-to-buf!
  [out in inlen k]
  (b/call! shorthash out in inlen k))

(defn shorthash [in k]
  "Computes a fixed-size fingerprint for the message `in`,
  using the key `k`."
  (let [out (bb/alloc bytes)]
    (shorthash-to-buf!
     out
     (bb/->indirect-byte-buf in)
     (bb/buflen in)
     (bb/->indirect-byte-buf k))
    out))
