(ns caesium.crypto.hash-test
  (:require [caesium.crypto.hash :as h]
            [caesium.util :refer [array-eq]]
            [caesium.vectors :as v]
            [caesium.test-utils :refer [const-test]]
            [clojure.test :refer [are deftest is]]))

(const-test
 h/sha256-bytes 32
 h/sha512-bytes 64)

(def ^:private hash-vector
  (comp v/hex-resource (partial str "vectors/hash/")))

(def empty-string (byte-array 0))

(def ^:private sha256-vector
  (comp hash-vector (partial str "sha256/")))

(def sha256-message
  (.getBytes "My Bonnie lies over the ocean, my Bonnie lies over the sea"))

(deftest sha-256-test
  (are [f message expected] (array-eq expected (f message))
    h/sha256 sha256-message (sha256-vector "digest-0")
    h/sha256 empty-string (sha256-vector "digest-empty-string")))

(def ^:private sha512-vector
  (comp hash-vector (partial str "sha512/")))

(def sha512-message
  (.getBytes "My Bonnie lies over the ocean, Oh bring back my Bonnie to me"))

(deftest sha-512-test
  (are [f message expected] (array-eq expected (f message))
    h/sha512 sha512-message (sha512-vector "digest-0")
    h/sha512 empty-string (sha512-vector "digest-empty-string")))
