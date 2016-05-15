(ns caesium.crypto.sign-test
  (:require [caesium.crypto.sign :as s]
            [caesium.util :as u]
            [caesium.vectors :refer [hex-resource]]
            [clojure.test :refer [deftest is testing]]
            [caesium.test-utils :refer [const-test]]))

(const-test
 s/bytes 64
 s/seedbytes 32
 s/publickeybytes 32
 s/secretkeybytes 64
 s/primitive "ed25519")

(deftest generate-signing-keys-test
  (let [kp1 (s/generate-signing-keys)
        kp2 (s/generate-signing-keys)]
    (is (not (u/array-eq (:public kp1) (:public kp2))))
    (is (not (u/array-eq (:secret kp1) (:secret kp2))))))

(def sign-resource (comp hex-resource (partial str "vectors/sign/")))
(def seed (sign-resource "seed"))
(def secret (sign-resource "secret"))
(def public (sign-resource "public"))
(def message (sign-resource "message"))
(def signature (sign-resource "signature"))

(deftest pair-from-secret-test
  (let [kp (s/generate-signing-keys seed)]
    (is (u/array-eq public (:public kp)))
    (is (u/array-eq secret (:secret kp)))))

(deftest detached-sign-test
  (is (u/array-eq signature (s/sign secret message))))

(deftest detached-verify-test
  (is (nil? (s/verify public message signature)))
  (let [{pk :public sk :secret} (s/generate-signing-keys)]
    (is (nil? (s/verify pk message (s/sign sk message)))))
  (is (thrown-with-msg?
       RuntimeException #"^Signature validation failed$"
       (let [{pk :public sk :secret} (s/generate-signing-keys)
             other-sig (s/sign sk message)]
         (s/verify public message other-sig)))))
