(ns caesium.crypto.aead-test
  (:require [caesium.crypto.aead :as aead]
            [caesium.test-utils :refer [const-test]]
            [caesium.vectors :as v]
            [clojure.test :refer [is deftest]]
            [caesium.util :as u]
            [caesium.byte-bufs :as bb]))

(const-test
 aead/chacha20poly1305-ietf-keybytes 32
 aead/chacha20poly1305-ietf-nsecbytes 0
 aead/chacha20poly1305-ietf-npubbytes 12
 aead/chacha20poly1305-ietf-abytes 16

 aead/chacha20poly1305-keybytes 32
 aead/chacha20poly1305-nsecbytes 0
 aead/chacha20poly1305-npubbytes 8
 aead/chacha20poly1305-abytes 16

 aead/xchacha20poly1305-ietf-keybytes 32
 aead/xchacha20poly1305-ietf-nsecbytes 0
 aead/xchacha20poly1305-ietf-npubbytes 24
 aead/xchacha20poly1305-ietf-abytes 16)

(def aead-chacha20poly1305-ietf-vector
  (comp v/hex-resource (partial str "vectors/aead/chacha20poly1305ietf/")))

(deftest chacha20poly1305-ietf-encrypt-decrypt-test
  (let [k (aead-chacha20poly1305-ietf-vector "key")
        ptext (aead-chacha20poly1305-ietf-vector "plaintext")
        ctext (aead-chacha20poly1305-ietf-vector "ciphertext-0")
        ad (aead-chacha20poly1305-ietf-vector "ad")
        nonce (aead-chacha20poly1305-ietf-vector "nonce")
        generated-nonce (aead/new-chacha20poly1305-ietf-nonce)
        generated-keygen (aead/chacha20poly1305-ietf-keygen)]
    (is (bb/bytes= ctext (aead/chacha20poly1305-ietf-encrypt ptext ad nonce k)))
    (is (bb/bytes= ptext (aead/chacha20poly1305-ietf-decrypt ctext ad nonce k)))
    (is (bb/bytes= ptext (aead/chacha20poly1305-ietf-decrypt
                          (aead/chacha20poly1305-ietf-encrypt ptext ad generated-nonce generated-keygen)
                          ad generated-nonce generated-keygen)))))

(deftest chacha20poly1305-ietf-encrypt-decrypt-detached-test
  (let [k (aead-chacha20poly1305-ietf-vector "key")
        ptext (aead-chacha20poly1305-ietf-vector "plaintext")
        ctext (aead-chacha20poly1305-ietf-vector "ciphertext-1")
        mtext (aead-chacha20poly1305-ietf-vector "mac")
        ad (aead-chacha20poly1305-ietf-vector "ad")
        nonce (aead-chacha20poly1305-ietf-vector "nonce")
        {:keys [c mac]} (aead/chacha20poly1305-ietf-encrypt-detached ptext ad nonce k)]
    (is (bb/bytes= ctext c))
    (is (bb/bytes= mtext mac))
    (is (bb/bytes= ptext (aead/chacha20poly1305-ietf-decrypt-detached ctext mac ad nonce k)))))

(def aead-chacha20poly1305-vector
  (comp v/hex-resource (partial str "vectors/aead/chacha20poly1305/")))

(deftest chacha20poly1305-encrypt-decrypt-test
  (let [k (aead-chacha20poly1305-vector "key")
        ptext (aead-chacha20poly1305-vector "plaintext")
        ctext (aead-chacha20poly1305-vector "ciphertext-0")
        ad (aead-chacha20poly1305-vector "ad")
        nonce (aead-chacha20poly1305-vector "nonce")
        generated-nonce (aead/new-chacha20poly1305-nonce)
        generated-keygen (aead/chacha20poly1305-keygen)]
    (is (bb/bytes= ctext (aead/chacha20poly1305-encrypt ptext ad nonce k)))
    (is (bb/bytes= ptext (aead/chacha20poly1305-decrypt ctext ad nonce k)))
    (is (bb/bytes= ptext (aead/chacha20poly1305-decrypt
                          (aead/chacha20poly1305-encrypt ptext ad generated-nonce generated-keygen)
                          ad generated-nonce generated-keygen)))))

(deftest chacha20poly1305-encrypt-decrypt-detached-test
  (let [k (aead-chacha20poly1305-vector "key")
        ptext (aead-chacha20poly1305-vector "plaintext")
        ctext (aead-chacha20poly1305-vector "ciphertext-1")
        mtext (aead-chacha20poly1305-vector "mac")
        ad (aead-chacha20poly1305-vector "ad")
        nonce (aead-chacha20poly1305-vector "nonce")
        {:keys [c mac]} (aead/chacha20poly1305-encrypt-detached ptext ad nonce k)]
    (is (bb/bytes= ctext c))
    (is (bb/bytes= mtext mac))
    (is (bb/bytes= ptext (aead/chacha20poly1305-decrypt-detached ctext mac ad nonce k)))))

(def aead-xchacha20poly1305-ietf-vector
  (comp v/hex-resource (partial str "vectors/aead/xchacha20poly1305ietf/")))

(deftest xchacha20poly1305-ietf-encrypt-decrypt-test
  (let [k (aead-xchacha20poly1305-ietf-vector "key")
        ptext (aead-xchacha20poly1305-ietf-vector "plaintext")
        ad (aead-xchacha20poly1305-ietf-vector "ad")
        nonce (aead/new-xchacha20poly1305-ietf-nonce)
        generated-key (aead/xchacha20poly1305-ietf-keygen)]
    (is (bb/bytes= ptext (aead/xchacha20poly1305-ietf-decrypt
                          (aead/xchacha20poly1305-ietf-encrypt ptext ad nonce k) ad nonce k)))
    (is (bb/bytes= ptext (aead/xchacha20poly1305-ietf-decrypt
                          (aead/xchacha20poly1305-ietf-encrypt ptext ad nonce generated-key) ad nonce generated-key)))))

(deftest xchacha20poly1305-ietf-encrypt-decrypt-detached-test
  (let [k (aead-xchacha20poly1305-ietf-vector "key")
        ptext (aead-xchacha20poly1305-ietf-vector "plaintext")
        ad (aead-xchacha20poly1305-ietf-vector "ad")
        nonce (aead/new-xchacha20poly1305-ietf-nonce)
        {:keys [c mac]} (aead/xchacha20poly1305-ietf-encrypt-detached ptext ad nonce k)]
    (is (bb/bytes= ptext (aead/xchacha20poly1305-ietf-decrypt-detached c mac ad nonce k)))))
