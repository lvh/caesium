(ns caesium.crypto.auth-test
  (:require [caesium.crypto.auth :as a]
            [caesium.test-utils :refer [const-test]]
            [caesium.vectors :as v]
            [clojure.test :refer [are deftest]]
            [caesium.byte-bufs :as bb]))

(const-test
 a/hmacsha256-bytes 32
 a/hmacsha256-keybytes 32
 a/hmacsha512-bytes 64
 a/hmacsha512-keybytes 32
 a/hmacsha512256-bytes 32
 a/hmacsha512256-keybytes 32)

(def ^:private hash-vector
  (comp v/hex-resource (partial str "vectors/auth/")))

(def ^:private hmacsha256-vector
  (comp hash-vector (partial str "hmacsha256/")))

(deftest sha-256-test
  (are [f message key expected] (bb/bytes= expected (f message key))
    a/hmacsha256 (hmacsha256-vector "message") (hmacsha256-vector "key") (hmacsha256-vector "mac")))

(def ^:private hmacsha512-vector
  (comp hash-vector (partial str "hmacsha512/")))

(deftest sha-512-test
  (are [f message key expected] (bb/bytes= expected (f message key))
    a/hmacsha512 (hmacsha512-vector "message") (hmacsha512-vector "key") (hmacsha512-vector "mac")))

(def ^:private hmacsha512256-vector
  (comp hash-vector (partial str "hmacsha512256/")))

(deftest sha-512256-test
  (are [f message key expected] (bb/bytes= expected (f message key))
    a/hmacsha512256 (hmacsha512256-vector "message") (hmacsha512256-vector "key") (hmacsha512256-vector "mac")))
