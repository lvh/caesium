(ns caesium.crypto.kx-test
  (:require [caesium.crypto.kx :as kx]
            [caesium.byte-bufs :as bb]
            [caesium.randombytes :as r]
            [caesium.test-utils :refer [const-test]]
            [caesium.vectors :as v]
            [clojure.test :refer [deftest is testing]]))

(const-test
 kx/seedbytes 32
 kx/publickeybytes 32
 kx/secretkeybytes 32
 kx/sessionkeybytes 32
 kx/primitive "x25519blake2b")

(def kx-vector
  (comp v/hex-resource (partial str "vectors/kx/")))

(deftest keypair-generation-test
  (testing "generates new keypair, with preallocated buffer"
    (is (let [pk1 (bb/alloc kx/publickeybytes)
              sk1 (bb/alloc kx/secretkeybytes)
              pk2 (bb/alloc kx/publickeybytes)
              sk2 (bb/alloc kx/secretkeybytes)
              _ (kx/keypair-to-buf! pk1 sk1)
              _ (kx/keypair-to-buf! pk2 sk2)]
          (and (not (bb/bytes= pk1 pk2))
               (not (bb/bytes= sk1 sk2))))))
  (testing "generates new keypair from seed, with preallocated buffer"
    (let [pk1 (bb/alloc kx/publickeybytes)
          sk1 (bb/alloc kx/secretkeybytes)
          pk2 (bb/alloc kx/publickeybytes)
          sk2 (bb/alloc kx/secretkeybytes)
          seed (bb/->indirect-byte-buf (r/randombytes kx/seedbytes))
          _ (kx/keypair-to-buf! pk1 sk1 seed)
          _ (kx/keypair-to-buf! pk2 sk2 seed)]
      (is (bb/bytes= pk1 pk2))
      (is (bb/bytes= sk1 sk2))))
  (testing "generates new keypairs"
    (is (let [kp1 (kx/keypair!)
              kp2 (kx/keypair!)]
          (and (not (bb/bytes= (:public kp1) (:public kp2)))
               (not (bb/bytes= (:secret kp1) (:secret kp2)))))))
  (testing "generate public key from seed"
    (let [seed (bb/->indirect-byte-buf (r/randombytes kx/seedbytes))
          kp1 (kx/keypair! seed)
          kp2 (kx/keypair! seed)]
      (is (bb/bytes= (:public kp1) (:public kp2)))
      (is (bb/bytes= (:secret kp1) (:secret kp2)))))
  (testing "generate public key from secret key"
    (let [kp1 (kx/keypair!)
          kp2 (kx/sk->keypair (:secret kp1))]
      (is (bb/bytes= (:public kp1) (:public kp2)))
      (is (bb/bytes= (:secret kp1) (:secret kp2))))))

(deftest invalid-input-test
  (testing "check exception is thrown when inputs are invalid"
    (let [rx (bb/alloc 0)
          tx (bb/alloc 0)
          pk (bb/alloc (* 2 kx/publickeybytes))
          sk (bb/alloc (* 2 kx/secretkeybytes))
          spk (bb/alloc (* 2 kx/publickeybytes))
          result (try (kx/client-session-keys-to-buf! rx tx pk sk spk) (catch Exception e e))]
      (is (= (type result) (type (RuntimeException.))))))
  (testing "check exception is thrown when inputs are invalid"
    (let [rx (bb/alloc 0)
          tx (bb/alloc 0)
          pk (bb/alloc (* 2 kx/publickeybytes))
          sk (bb/alloc (* 2 kx/secretkeybytes))
          spk (bb/alloc (* 2 kx/publickeybytes))
          result (try (kx/server-session-keys-to-buf! rx tx pk sk spk) (catch Exception e e))]
      (is (= (type result) (type (RuntimeException.)))))))

(deftest client-key-exchange-alice-test
  (testing "generate rx and tx keys from client keypair and server public key, with preallocated buffer"
    (let [rx (bb/alloc kx/sessionkeybytes)
          tx (bb/alloc kx/sessionkeybytes)
          pk (kx-vector "alice-public-key")
          sk (kx-vector "alice-secret-key")
          spk (kx-vector "bob-public-key")
          {rx :client-rx
           tx :client-tx} (kx/client-session-keys-to-buf! rx tx pk sk spk)]
      (is (bb/bytes= rx (kx-vector "client-alice-rx")))
      (is (bb/bytes= tx (kx-vector "client-alice-tx")))))
  (testing "generate rx and tx keys from client keypair and server public key"
    (let [kp {:public (kx-vector "alice-public-key") :secret (kx-vector "alice-secret-key")}
          spk (kx-vector "bob-public-key")
          {rx :client-rx
           tx :client-tx} (kx/client-session-keys kp spk)]
      (is (bb/bytes= rx (kx-vector "client-alice-rx")))
      (is (bb/bytes= tx (kx-vector "client-alice-tx")))))
  (testing "generate rx and tx keys from client keys and server public key"
    (let [pk (kx-vector "alice-public-key")
          sk (kx-vector "alice-secret-key")
          spk (kx-vector "bob-public-key")
          {rx :client-rx
           tx :client-tx} (kx/client-session-keys pk sk spk)]
      (is (bb/bytes= rx (kx-vector "client-alice-rx")))
      (is (bb/bytes= tx (kx-vector "client-alice-tx"))))))

(deftest client-key-exchange-bob-test
  (testing "generate rx and tx keys from client keypair and server public key, with preallocated buffer"
    (let [rx (bb/alloc kx/sessionkeybytes)
          tx (bb/alloc kx/sessionkeybytes)
          pk (kx-vector "bob-public-key")
          sk (kx-vector "bob-secret-key")
          spk (kx-vector "alice-public-key")
          {rx :client-rx
           tx :client-tx} (kx/client-session-keys-to-buf! rx tx pk sk spk)]
      (is (bb/bytes= rx (kx-vector "client-bob-rx")))
      (is (bb/bytes= tx (kx-vector "client-bob-tx")))))
  (testing "generate rx and tx keys from client keypair and server public key"
    (let [kp {:public (kx-vector "bob-public-key") :secret (kx-vector "bob-secret-key")}
          spk (kx-vector "alice-public-key")
          {rx :client-rx
           tx :client-tx} (kx/client-session-keys kp spk)]
      (is (bb/bytes= rx (kx-vector "client-bob-rx")))
      (is (bb/bytes= tx (kx-vector "client-bob-tx")))))
  (testing "generate rx and tx keys from client keys and server public key"
    (let [pk (kx-vector "bob-public-key")
          sk (kx-vector "bob-secret-key")
          spk (kx-vector "alice-public-key")
          {rx :client-rx
           tx :client-tx} (kx/client-session-keys pk sk spk)]
      (is (bb/bytes= rx (kx-vector "client-bob-rx")))
      (is (bb/bytes= tx (kx-vector "client-bob-tx"))))))

(deftest server-key-exchange-alice-test
  (testing "generate rx and tx keys from server keypair and client public key, with preallocated buffer"
    (let [rx (bb/alloc kx/sessionkeybytes)
          tx (bb/alloc kx/sessionkeybytes)
          pk (kx-vector "alice-public-key")
          sk (kx-vector "alice-secret-key")
          cpk (kx-vector "bob-public-key")
          {rx :server-rx
           tx :server-tx} (kx/server-session-keys-to-buf! rx tx pk sk cpk)]
      (is (bb/bytes= rx (kx-vector "server-alice-rx")))
      (is (bb/bytes= tx (kx-vector "server-alice-tx")))))
  (testing "generate rx and tx keys from server keypair and client public key"
    (let [kp {:public (kx-vector "alice-public-key") :secret (kx-vector "alice-secret-key")}
          cpk (kx-vector "bob-public-key")
          {rx :server-rx
           tx :server-tx} (kx/server-session-keys kp cpk)]
      (is (bb/bytes= rx (kx-vector "server-alice-rx")))
      (is (bb/bytes= tx (kx-vector "server-alice-tx")))))
  (testing "generate rx and tx keys from server keys and client public key"
    (let [pk (kx-vector "alice-public-key")
          sk (kx-vector "alice-secret-key")
          cpk (kx-vector "bob-public-key")
          {rx :server-rx
           tx :server-tx} (kx/server-session-keys pk sk cpk)]
      (is (bb/bytes= rx (kx-vector "server-alice-rx")))
      (is (bb/bytes= tx (kx-vector "server-alice-tx"))))))

(deftest server-key-exchange-bob-test
  (testing "generate rx and tx keys from server keypair and client public key, with preallocated buffer"
    (let [rx (bb/alloc kx/sessionkeybytes)
          tx (bb/alloc kx/sessionkeybytes)
          pk (kx-vector "bob-public-key")
          sk (kx-vector "bob-secret-key")
          cpk (kx-vector "alice-public-key")
          {rx :server-rx
           tx :server-tx} (kx/server-session-keys-to-buf! rx tx pk sk cpk)]
      (is (bb/bytes= rx (kx-vector "server-bob-rx")))
      (is (bb/bytes= tx (kx-vector "server-bob-tx")))))
  (testing "generate rx and tx keys from server keypair and client public key"
    (let [kp {:public (kx-vector "bob-public-key") :secret (kx-vector "bob-secret-key")}
          cpk (kx-vector "alice-public-key")
          {rx :server-rx
           tx :server-tx} (kx/server-session-keys kp cpk)]
      (is (bb/bytes= rx (kx-vector "server-bob-rx")))
      (is (bb/bytes= tx (kx-vector "server-bob-tx")))))
  (testing "generate rx and tx keys from server keys and client public key"
    (let [pk (kx-vector "bob-public-key")
          sk (kx-vector "bob-secret-key")
          cpk (kx-vector "alice-public-key")
          {rx :server-rx
           tx :server-tx} (kx/server-session-keys pk sk cpk)]
      (is (bb/bytes= rx (kx-vector "server-bob-rx")))
      (is (bb/bytes= tx (kx-vector "server-bob-tx"))))))
