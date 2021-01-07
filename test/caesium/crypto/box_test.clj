
(ns caesium.crypto.box-test
  (:require [caesium.crypto.box :as b]
            [caesium.byte-bufs :as bb]
            [caesium.randombytes :as r]
            [caesium.test-utils :refer [const-test]]
            [caesium.vectors :as v]
            [clojure.test :refer [deftest is testing]]))

(const-test
 b/seedbytes 32
 b/publickeybytes 32
 b/secretkeybytes 32
 b/noncebytes 24
 b/macbytes 16
 b/primitive "curve25519xsalsa20poly1305")

(deftest keypair-generation-test
  (testing "generates new keypairs"
    (is (let [kp1 (b/keypair!)
              kp2 (b/keypair!)]
          (and (not (bb/bytes= (:public kp1) (:public kp2)))
               (not (bb/bytes= (:secret kp1) (:secret kp2)))))))
  (testing "generate public key from seed"
    (let [seed (bb/->indirect-byte-buf (r/randombytes b/seedbytes))
          kp1 (b/keypair! seed)
          kp2 (b/keypair! seed)]
      (is (bb/bytes= (:public kp1) (:public kp2)))
      (is (bb/bytes= (:secret kp1) (:secret kp2)))))
  (testing "generate public key from secret key"
    (let [kp1 (b/keypair!)
          kp2 (b/sk->keypair (:secret kp1))]
      (is (bb/bytes= (:public kp1) (:public kp2)))
      (is (bb/bytes= (:secret kp1) (:secret kp2))))))

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
    (is (bb/bytes= ctext (b/encrypt alice-pk bob-sk nonce ptext)))
    (is (bb/bytes= ptext (b/decrypt bob-pk alice-sk nonce ctext)))
    (let [forgery (r/randombytes (alength ^bytes ctext))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (b/decrypt bob-pk alice-sk nonce forgery))))))

(deftest anonymous-encrypt-decrypt-test
  (let [ptext (box-vector "plaintext")
        bob-pk (box-vector "bob-public-key")
        bob-sk (box-vector "bob-secret-key")
        ctext (b/anonymous-encrypt bob-pk ptext)]
    (is (not (bb/bytes= ptext ctext)))
    (is (bb/bytes= ptext (b/anonymous-decrypt bob-pk bob-sk ctext)))
    (let [forgery (r/randombytes (alength ^bytes ctext))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (b/anonymous-decrypt bob-pk bob-sk forgery))))))

(deftest detached-test
  (let [nonce (box-vector "nonce")
        ptext (box-vector "plaintext")
        c-kat (box-vector "ciphertext")
        bob-pk (box-vector "bob-public-key")
        bob-sk (box-vector "bob-secret-key")
        alice-pk (box-vector "alice-public-key")
        alice-sk (box-vector "alice-secret-key")
        {:keys [c mac]} (b/box-detached ptext nonce alice-pk bob-sk)
        open-detached (b/box-open-detached c mac nonce bob-pk alice-sk)]
    (is (bb/bytes= (byte-array (drop b/macbytes c-kat)) c))
    (is (bb/bytes= (byte-array (take b/macbytes c-kat)) mac))
    (is (bb/bytes= ptext open-detached))
    (let [forged-c (r/randombytes (- (alength ^bytes c-kat) b/macbytes))
          forged-mac (r/randombytes b/macbytes)]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (b/box-open-detached forged-c forged-mac nonce bob-pk alice-sk))))))
