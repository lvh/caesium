(ns caesium.crypto.sign-test
  (:require [caesium.crypto.sign :as s]
            [caesium.byte-bufs :as bb]
            [caesium.vectors :refer [hex-resource]]
            [clojure.test :refer [deftest is]]
            [caesium.test-utils :refer [const-test]]))

(const-test
 s/bytes 64
 s/seedbytes 32
 s/publickeybytes 32
 s/secretkeybytes 64
 s/primitive "ed25519")

(deftest generate-signing-keys-alias-test
  (is (= s/generate-signing-keys s/keypair!)))

(deftest generate-signing-keys-test
  (let [kp1 (s/keypair!)
        kp2 (s/keypair!)]
    (is (not (bb/bytes= (:public kp1) (:public kp2))))
    (is (not (bb/bytes= (:secret kp1) (:secret kp2))))))

(def sign-resource (comp hex-resource (partial str "vectors/sign/")))
(def seed (sign-resource "seed"))
(def secret (sign-resource "secret"))
(def public (sign-resource "public"))
(def message (sign-resource "message"))
(def signature (sign-resource "signature"))
(def signed (sign-resource "signed"))

(deftest pair-from-secret-test
  (let [kp (s/keypair! seed)]
    (is (bb/bytes= public (:public kp)))
    (is (bb/bytes= secret (:secret kp)))))

(deftest detached-sign-test
  (is (bb/bytes= signature (s/sign message secret))))

(deftest detached-verify-test
  (is (nil? (s/verify signature message public)))
  (let [{pk :public sk :secret} (s/keypair!)]
    (is (nil? (s/verify (s/sign message sk) message pk))))
  (is (thrown-with-msg?
       RuntimeException #"^Signature validation failed$"
       (let [{_pk :public sk :secret} (s/keypair!)
             other-sig (s/sign message sk)]
         (s/verify other-sig message public)))))

(deftest signed-test
  (is (bb/bytes= signed (s/signed message secret))))

(deftest signed-verify-test
  (is (bb/bytes= message (s/verify signed public)))
  (is (thrown-with-msg?
       RuntimeException #"^Signature validation failed$"
       (let [{_pk :public sk :secret} (s/keypair!)
             other-signed (s/signed message sk)]
         (s/verify other-signed public)))))
