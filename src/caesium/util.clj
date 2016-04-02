(ns caesium.util
  (:import (java.util Arrays)
           (org.abstractj.kalium.encoders Encoder)))

(defn array-eq
  "Compares two byte arrays for equality."
  [^bytes a ^bytes b]
  (Arrays/equals a b))

(defn unhexify [s]
  (.decode Encoder/HEX s))

(defn hexify [b]
  (.encode Encoder/HEX b))
