(ns caesium.crypto.box-test
  (:require [caesium.crypto.box :as b]
            [caesium.crypto.scalarmult :as s]
            [caesium.util :as u]
            [caesium.vectors :as v]
            [clojure.test :refer [are deftest is testing]]))

(deftest const-tests
  (are [const expected] (= expected const)
    b/seedbytes 32
    b/publickeybytes 32
    b/secretkeybytes 32
    b/noncebytes 24
    b/macbytes 16
    b/primitive "curve25519xsalsa20poly1305"))

(deftest keypair-generation-test
  (testing "generates new keypairs"
    (is (let [kp1 (b/generate-keypair)
              kp2 (b/generate-keypair)]
          (and (not (u/array-eq (:public kp1) (:public kp2)))
               (not (u/array-eq (:secret kp1) (:secret kp2)))))))
  (testing "generate public key from seed"
    (let [seed (s/int->scalar 1)
          kp1 (b/generate-keypair seed)
          kp2 (b/generate-keypair seed)]
      (is (u/array-eq (:public kp1) (:public kp2)))
      (is (u/array-eq (:secret kp1) (:secret kp2)))))
  (testing "generate public key from secret key"
    (let [kp1 (b/generate-keypair)
          kp2 (b/sk->keypair (:secret kp1))]
      (is (u/array-eq (:public kp1) (:public kp2)))
      (is (u/array-eq (:secret kp1) (:secret kp2))))))

(def box-vector
  (comp v/hex-resource (partial str "vectors/box/")))

(deftest encrypt-decrypt-test
  (let [nonce (box-vector "nonce")
        ptext (box-vector "plaintext")
        ctext (box-vector "ciphertext")
        bob-pk (box-vector "bob-public-key")
        bob-sk (box-vector "bob-secret-key")
        alice-pk (box-vector "alice-public-key")
        alice-sk (box-vector "alice-secret-key")]
    (is (u/array-eq ctext (b/encrypt alice-pk bob-sk nonce ptext)))
    (is (u/array-eq ptext (b/decrypt bob-pk alice-sk nonce ctext)))
    (let [pk (u/hexify alice-pk)
          sk (u/hexify bob-sk)]
      (is (thrown? ClassCastException (b/encrypt pk sk nonce ptext))))))
