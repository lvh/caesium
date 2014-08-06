(ns caesium.crypto.hash
  (:import (org.abstractj.kalium.crypto Hash)))

(defn blake2 [message]
  (.blake2 (new Hash) message))
