(ns caesium.crypto.kdf-test
  (:require [caesium.byte-bufs :as bb]
            [caesium.crypto.kdf :as sut]
            [caesium.test-utils :refer [const-test]]
            [caesium.vectors :as v]
            [clojure.test :refer [deftest is]]))

(const-test
 sut/bytes-min 16
 sut/bytes-max 64
 sut/contextbytes 8
 sut/keybytes 32
 sut/primitive "blake2b")

(def kdf-vectors
  (comp v/hex-resources (partial str "vectors/kdf/")))

(def derived-keys (kdf-vectors "derived-keys"))
(def derived-keys-2 (kdf-vectors "derived-keys-2"))

(deftest derive-from-key-test
  ;; This is a direct port of the libsodium KDF test found at:
  ;; https://github.com/jedisct1/libsodium/blob/a6d317b2f316fa86896ec857afab43ff70aadab0/test/default/kdf.c#L6
  (let [master-key (byte-array 32 (range sut/keybytes))
        ctx "KDF test"]
    (doseq [[i target] (partition 2 (interleave (range 10) derived-keys))]
      (let [subkey (sut/derive-from-key sut/bytes-max i ctx master-key)]
        (is (bb/bytes= subkey target))))
    (dotimes [i 16]
      (is (thrown? RuntimeException
                   (sut/derive-from-key i i ctx master-key))))
    (doseq [[i target] (partition 2
                                  (interleave (range 16 (inc sut/bytes-max))
                                              derived-keys-2))]
      (let [subkey (sut/derive-from-key i i ctx master-key)]
        (is (bb/bytes= subkey target))))
    (is (thrown? RuntimeException
                 (sut/derive-from-key
                  (inc sut/bytes-max) (inc sut/bytes-max) ctx master-key)))))

