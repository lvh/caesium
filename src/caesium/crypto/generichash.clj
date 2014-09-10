(ns caesium.crypto.generichash
  (:import (org.abstractj.kalium.crypto Hash)))

(def ^:private sixteen-nuls (repeat 16 (byte 0)))

(defn blake2b
  "Computes the BLAKE2b digest of the given message, with optional
  salt, key and personalization parameters."
  ([message]
     (.blake2 (new Hash) message))
  ([message & {salt :salt key :key personal :personal
               :or {salt sixteen-nuls
                    personal sixteen-nuls
                    key (byte-array 0)}}]
