(ns caesium.crypto.box-test
  (:require
   [caesium.crypto.box :as b]
   [caesium.util :as u]
   [clojure.test :refer :all]
   [caesium.vectors :as v]))

(deftest box-keypair-generation
  (testing "generates new keypairs"
    (is (let [kp1 (b/generate-keypair)
              kp2 (b/generate-keypair)]
          (and (not (u/array-eq (:public kp1) (:public kp2)))
               (not (u/array-eq (:secret kp1) (:secret kp2)))))))
  (testing "generate public key from secret key"
    (is (let [kp1 (b/generate-keypair)
              kp2 (b/generate-keypair (:secret kp1))]
          (u/array-eq (:public kp1) (:public kp2))))))

(def nonce (v/hex-resource "vectors/box/nonce"))
(def plaintext (v/hex-resource "vectors/box/plaintext"))
(def ciphertext (v/hex-resource "vectors/box/ciphertext"))
(def bob-secret-key (v/hex-resource "vectors/box/bob-secret-key"))
(def bob-public-key (v/hex-resource "vectors/box/bob-public-key"))
(def alice-secret-key (v/hex-resource "vectors/box/alice-secret-key"))
(def alice-public-key (v/hex-resource "vectors/box/alice-public-key"))

(deftest box-encrypt-decrypt-test
  (is (u/array-eq ciphertext
                  (b/encrypt alice-public-key bob-secret-key nonce plaintext))
      "Bob can encrypt a message for Alice")
  (is (u/array-eq plaintext
                  (b/decrypt bob-public-key alice-secret-key nonce ciphertext))
      "Alice can decrypt the message from Bob")
  (let [hex-public-key (u/hexify alice-public-key)
        hex-private-key (u/hexify bob-secret-key)]
    (is (thrown? java.lang.ClassCastException
                 (b/encrypt hex-public-key hex-private-key nonce plaintext))
        "encrypt does not accept strings")))
