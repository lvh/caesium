(ns caesium.crypto.generichash-test
  (:require [caesium.crypto.generichash :refer :all]
            [caesium.util :refer [unhexify array-eq]]
            [clojure.test :refer :all]))

(def empty-string-digest (unhexify "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"))

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
    (are [args expected] (array-eq (apply blake2b args)
                                   expected)
      [(byte-array [])] empty-string-digest
      [(byte-array [90])] (unhexify "4884256d056fb76f83f10ab85c127682d447d126d99dee526883488f57951fffb576a16d8a7fd391420e23b7c0cf14b413878de095dc3d84bcaecba0bc657c77")
      [(.getBytes "The quick brown fox jumps over the lazy dog")
       :key (.getBytes "This is a super secret key. Ssshh!")
       :salt (.getBytes "0123456789abcdef")
       :personal (.getBytes "fedcba9876543210")]
      (unhexify "9479874d504f0447d43d72a969c989c34032172276ac50077e0027277c3c8d867bee9ee314c8506e4e4a9b3030b989d3eb7b4c1826c8e0d56e6aa71b1d4cf388")))
  (testing "blake2b defaults are accurate"
    (doseq [args blake2b-empty-args-variations]
      (is (array-eq (apply blake2b args)
                    empty-string-digest)
          (str "args: " args)))))

(def empty-string (.getBytes ""))

(def sha256-message (.getBytes "My Bonnie lies over the ocean, my Bonnie lies over the sea"))
(def sha256-digest (unhexify "d281d10296b7bde20df3f3f4a6d1bdb513f4aa4ccb0048c7b2f7f5786b4bcb77"))
(def sha256-empty-string-digest (unhexify "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

(def sha512-message (.getBytes "My Bonnie lies over the ocean, Oh bring back my Bonnie to me"))
(def sha512-digest (unhexify "2823e0373001b5f3aa6db57d07bc588324917fc221dd27975613942d7f2e19bf444654c8b9f4f9cb908ef15f2304522e60e9ced3fdec66e34bc2afb52be6ad1c"))
(def sha512-empty-string-digest (unhexify "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"))

(deftest sha-256-512-test
  (testing "sha256 and 512 work directly"
    (are [f message expected] (array-eq expected (f message))
      sha256 sha256-message sha256-digest
      sha256 empty-string sha256-empty-string-digest
      sha512 sha512-message sha512-digest
      sha512 empty-string sha512-empty-string-digest)))
