(ns caesium.crypto.sign-test
  (:require [caesium.crypto.sign :as s]
            [caesium.util :as u]
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

;; Test values taken from Kalium's suite
(def secret
  (u/unhexify "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd"))
(def public
  (u/unhexify "77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb"))
(def message
  (u/unhexify "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460376d7f3ac22ff372c18f613f2ae2e856af40"))
(def signature
  (u/unhexify "6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509"))

(deftest pair-from-secret-test
  (is (u/array-eq public (:public (s/generate-signing-keys secret)))))

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
