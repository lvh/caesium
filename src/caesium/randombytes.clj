(ns caesium.randombytes
  (:import (org.abstractj.kalium.crypto Random)))

(def ^:private ^Random random (new Random))

(defn randombytes
  [n]
  (.randomBytes random n))
