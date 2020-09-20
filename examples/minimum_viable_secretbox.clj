(ns minimum-viable-secretbox
  (:refer-clojure :exclude [key])
  (:require [caesium.crypto.secretbox :as sb]))

(def key (sb/new-key!))
(def plaintext "Hello caesium!")
(def nonce (sb/int->nonce 0))
(def ciphertext (sb/encrypt key nonce (.getBytes ^String plaintext)))
(def roundtrip (String. ^bytes (sb/decrypt key nonce ciphertext)))
(assert (= plaintext roundtrip))
