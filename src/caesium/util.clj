(ns caesium.util
  (:import (java.util Arrays)
           (org.abstractj.kalium.encoders Encoder)))

(defn array-eq
  "Compares two byte arrays for equality.

  Please note that this is not constant time!"
  [^bytes a ^bytes b]
  (Arrays/equals a b))

(defn unhexify [s]
  (.decode Encoder/HEX s))

(defn hexify [b]
  (.encode Encoder/HEX b))

(defn n->bytes
  "Turns n into a byte array of length len."
  [len n]
  (let [unpadded (.toByteArray (biginteger n))
        bytelen (alength unpadded)
        output (byte-array len)]
    (System/arraycopy unpadded 0 output (- len bytelen) bytelen)
    output))
