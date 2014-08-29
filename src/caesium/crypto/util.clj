(ns caesium.crypto.util
  (:import (java.util Arrays)))

(defn array-eq [a b] (Arrays/equals a b))

(defn unhexify [s]
  (let [encoded-bytes (partition 2 s)
        hex-pair->int (fn [[x y]]
                        (unchecked-byte (Integer/parseInt (str x y) 16)))
        decoded-bytes (map hex-pair->int encoded-bytes)]
    (into-array Byte/TYPE decoded-bytes)))
