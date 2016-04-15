(ns caesium.crypto.hash-test
  (:require [caesium.crypto.hash :as h]
            [caesium.vectors :as v]
            [clojure.test :refer [deftest is are]]))

(def ^:private hash-vector
  (comp v/hex-resource (partial str "vectors/hash/")))

(def empty-string (byte-array 0))

(def sha256-message
  (.getBytes "My Bonnie lies over the ocean, my Bonnie lies over the sea"))

(def sha512-message
  (.getBytes "My Bonnie lies over the ocean, Oh bring back my Bonnie to me"))

(def ^:private sha256-vector
  (comp hash-vector (partial str "sha256/")))

(def ^:private sha512-vector
  (comp hash-vector (partial str "sha512/")))

(deftest sha-256-512-test
  "sha256 and 512 work directly"
  (are [f message expected] (array-eq expected (f message))
    sha256 sha256-message (sha256-vector "digest-0")
    sha256 empty-string (sha256-vector "digest-empty-string")

    sha512 sha512-message (sha512-vector "digest-0")
    sha512 empty-string (sha512-vector "digest-empty-string")))
