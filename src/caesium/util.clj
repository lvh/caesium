(ns caesium.util
  (:import (java.util Arrays)
           (org.abstractj.kalium.encoders Encoder)))

(defn array-eq [^bytes a ^bytes b]
  "Compares two byte arrays for equality."
  (Arrays/equals a b))

(defn unhexify [s]
  (.decode Encoder/HEX s))

(defn hexify [b]
  (.encode Encoder/HEX b))
