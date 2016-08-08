(ns caesium.util
  "Internal utilities."
  (:require [caesium.byte-bufs :as bb])
  (:import (java.util Arrays)
           (org.apache.commons.codec.binary Hex)))

(defn array-eq
  "Compares two byte arrays for equality.

  Inputs will be converted to bytes as required. Please note that this
  is not constant time!"
  [a b]
  (Arrays/equals (bb/->bytes a) (bb/->bytes b)))

(defn unhexify
  [^String s]
  (.decode (Hex.) (.getBytes s)))

(defn hexify
  [b]
  (Hex/encodeHexString b))

(defn n->bytes
  "Turns n into a byte array of length len."
  [len n]
  (let [unpadded (.toByteArray (biginteger n))
        bytelen (alength unpadded)
        output (byte-array len)]
    (System/arraycopy unpadded 0 output (- len bytelen) bytelen)
    output))
