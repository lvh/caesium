(ns caesium.crypto.secretbox-test
  (:require
   [caesium.crypto.secretbox :as s]
   [caesium.util :as u]
   [caesium.vectors :as v]
   [clojure.test :refer :all]))

(deftest const-tests
  (is (= 32 s/keybytes))
  (is (= 24 s/noncebytes))
  (is (= 16 s/macbytes))
  (is (= "xsalsa20poly1305" s/primitive)))

(def ptext (v/hex-resource "vectors/secretbox/plaintext"))
(def secret-key (byte-array (range 32)))

(def n0 (s/int->nonce 0))
(def n1 (s/int->nonce 1))

(deftest secretbox-kat-test
  (are [nonce ctext] (let [encrypted (s/encrypt secret-key nonce ptext)
                           decrypted (s/decrypt secret-key nonce ctext)]
                       (and (u/array-eq encrypted ctext)
                            (u/array-eq decrypted ptext)))
    n0 (v/hex-resource "vectors/secretbox/ciphertext0")
    n1 (v/hex-resource "vectors/secretbox/ciphertext1"))
  (are [nonce ciphertext]
      (thrown-with-msg?
       RuntimeException #"Decryption failed. Ciphertext failed verification"
       (s/decrypt secret-key nonce ciphertext))
    n1 (v/hex-resource "vectors/secretbox/forgery1")))

(deftest int->nonce-test
  (testing "Turning numbers into nonces works"
    (are [n expected] (u/array-eq expected (s/int->nonce n))
      0 (byte-array 24)
      0M (byte-array 24)
      1000000000000 (byte-array (into (vec (repeat 19 0))
                                      [-24 -44 -91 16 0])))))
