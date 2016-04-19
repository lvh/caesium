(ns caesium.crypto.generichash-test
  (:require
   [caesium.crypto.generichash :as g]
   [caesium.util :refer [unhexify array-eq]]
   [clojure.test :refer :all]
   [caesium.vectors :as v]
   [caesium.util :as u]
   [caesium.crypto.hash :as h]))

(deftest const-tests
  (are [const expected] (= expected const)
    32 g/bytes
    16 g/bytes-min
    64 g/bytes-max

    32 g/keybytes
    16 g/keybytes-min
    64 g/keybytes-max

    32 g/blake2b-bytes
    16 g/blake2b-bytes-min
    64 g/blake2b-bytes-max

    32 g/blake2b-keybytes
    16 g/blake2b-keybytes-min
    64 g/blake2b-keybytes-max

    16 g/blake2b-saltbytes
    16 g/blake2b-personalbytes))

(def blake2b-vector
  (comp v/hex-resource (partial str "vectors/generichash/blake2b/")))

(deftest generichash-kat-test
  (are [args expected] (array-eq (apply g/hash args) expected)
    [(byte-array [])
     {:size 64}]
    (blake2b-vector "digest-empty-string-64")

    [(byte-array [90])
     {:size 64}]
    (blake2b-vector "digest-Z-64")))

(deftest blake2b-kat-test
  (are [args expected] (array-eq (apply g/blake2b args) expected)
    [(byte-array [])
     {:size 64}]
    (blake2b-vector "digest-empty-string-64")

    [(byte-array [90])
     {:size 64}]
    (blake2b-vector "digest-Z-64")

    [(.getBytes "The quick brown fox jumps over the lazy dog")
     {:size 64
      :key (.getBytes "This is a super secret key. Ssshh!")
      :salt (.getBytes "0123456789abcdef")
      :personal (.getBytes "fedcba9876543210")}]
    (blake2b-vector "digest-with-key-salt-personal-64")))

(def blake2b-empty-args-variations
  "All of the different ways you could spell that you want the digest
  of the empty string: with or without key, salt, and
  personalization.

  When given to the blake2b function, all of these should return the
  empty string digest."
  (for [key-expr [nil {:key (byte-array 0)}]
        salt-expr [nil {:salt (byte-array 16)}]
        personal-expr [nil {:personal (byte-array 16)}]]
    [(byte-array 0) (merge key-expr salt-expr personal-expr)]))

(deftest blake2b-empty-args-variations-tests
  (doseq [args blake2b-empty-args-variations]
    (is (array-eq (apply g/blake2b args) (blake2b-vector "digest-empty-string"))
        (str "args: " args))))
