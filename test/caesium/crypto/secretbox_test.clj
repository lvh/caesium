(ns caesium.crypto.secretbox-test
  (:require [caesium.crypto.secretbox :as s]
            [caesium.test-utils :refer [const-test]]
            [caesium.util :as u]
            [caesium.vectors :as v]
            [clojure.test :refer [is are deftest testing]]
            [caesium.byte-bufs :as bb]))

(const-test
 s/keybytes 32
 s/noncebytes 24
 s/macbytes 16
 s/primitive "xsalsa20poly1305")

;; Secretbox Constants
(def ptext (v/hex-resource "vectors/secretbox/plaintext"))
(def secret-key (byte-array (range 32)))

(def n0 (s/int->nonce 0))
(def n1 (s/int->nonce 1))

;; Secretbox Detached Constants
(def detached-ptext (v/hex-resource "vectors/secretbox/detached/plaintext0"))
(def detached-secret-key (byte-array (v/hex-resource "vectors/secretbox/detached/key0")))

(def detached-n0 (v/hex-resource "vectors/secretbox/detached/nonce0"))

(deftest secretbox-kat-test
  (are [nonce ctext] (let [encrypted (s/encrypt secret-key nonce ptext)
                           decrypted (s/decrypt secret-key nonce ctext)]
                       (and (bb/bytes= encrypted ctext)
                            (bb/bytes= decrypted ptext)))
    n0 (v/hex-resource "vectors/secretbox/ciphertext0")
    n1 (v/hex-resource "vectors/secretbox/ciphertext1"))
  (are [nonce ciphertext]
       (thrown-with-msg?
        RuntimeException #"Ciphertext verification failed"
        (s/decrypt secret-key nonce ciphertext))
    n1 (v/hex-resource "vectors/secretbox/forgery1")))

(deftest secretbox-detached-kat-test
  "Test vectors from:
  https://github.com/jedisct1/libsodium/blob/master/test/default/secretbox.c
  https://github.com/jedisct1/libsodium/blob/master/test/default/secretbox.exp"
  (let [{:keys [mac c]} (s/secretbox-detached detached-ptext detached-n0 detached-secret-key)
        known-answer-cipher-text (v/hex-resource "vectors/secretbox/detached/ciphertext0")
        decrypted (s/secretbox-open-detached c mac detached-n0 detached-secret-key)]
    (is (bb/bytes= c (byte-array (drop 16 known-answer-cipher-text))))
    (is (bb/bytes= mac (byte-array (take 16 known-answer-cipher-text))))
    (is (bb/bytes= decrypted detached-ptext))))

(deftest new-key!-test
  (let [[f & rs] (repeatedly 10 s/new-key!)]
    (doseq [r rs]
      (is (not (bb/bytes= f r))))))

(deftest int->nonce-test
  (testing "Turning numbers into nonces works"
    (are [n expected] (bb/bytes= expected (s/int->nonce n))
      0 (byte-array 24)
      0M (byte-array 24)
      1000000000000 (byte-array (into (vec (repeat 19 0))
                                      [-24 -44 -91 16 0])))))
