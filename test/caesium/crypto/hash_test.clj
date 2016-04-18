(ns caesium.crypto.hash-test
  (:require [caesium.crypto.hash :as h]
            [caesium.vectors :as v]
            [clojure.test :refer [deftest is are testing]]
            [caesium.util :refer [array-eq]]))

(deftest const-tests
  (is (= h/sha256-bytes 32))
  (is (= h/sha512-bytes 64)))

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
  (are [f message expected] (array-eq expected (f message))
    h/sha256 sha256-message (sha256-vector "digest-0")
    h/sha256 empty-string (sha256-vector "digest-empty-string")

    h/sha512 sha512-message (sha512-vector "digest-0")
    h/sha512 empty-string (sha512-vector "digest-empty-string")))

(def ^:private blake2b-vector
  (comp hash-vector (partial str "blake2b/")))

(def blake2b-empty-string-digest
  (blake2b-vector "digest-empty-string"))

(def blake2b-empty-args-variations
  "All of the different ways you could spell that you want the digest
  of the empty string: with or without key, salt, and
  personalization.

  When given to the blake2b function, all of these should return the
  empty string digest."
  (for [key-expr [[] [:key (byte-array 0)]]
        salt-expr [[] [:salt (byte-array 16)]]
        personal-expr [[] [:personal (byte-array 16)]]]
    (concat [(byte-array 0)] key-expr salt-expr personal-expr)))

(deftest blake2b-kat-test
  (testing "blake2b works directly"
    (are [args expected] (array-eq (apply h/blake2b args) expected)
      [(byte-array [])]
      blake2b-empty-string-digest

      [(byte-array [90])]
      (blake2b-vector "digest-0")

      [(.getBytes "The quick brown fox jumps over the lazy dog")
       :key (.getBytes "This is a super secret key. Ssshh!")
       :salt (.getBytes "0123456789abcdef")
       :personal (.getBytes "fedcba9876543210")]
      (blake2b-vector "digest-with-key-salt-personal")))
  (testing "blake2b defaults are accurate"
    (doseq [args blake2b-empty-args-variations]
      (is (array-eq (apply h/blake2b args) blake2b-empty-string-digest)
          (str "args: " args)))))
