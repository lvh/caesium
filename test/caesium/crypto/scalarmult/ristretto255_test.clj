(ns caesium.crypto.scalarmult.ristretto255-test
  "The Ristretto255 scalar multiplication tests ported from:
  https://github.com/jedisct1/libsodium/blob/master/test/default/scalarmult_ristretto255.c"
  (:require [caesium.byte-bufs :as bb]
            [caesium.crypto.scalarmult.ristretto255 :as s]
            [caesium.test-utils :refer [const-test]]
            [caesium.util :as u]
            [caesium.vectors :as v]
            [clojure.test :refer [are deftest is testing]]))

(const-test
 s/bytes 32
 s/scalarbytes 32)

(def ristretto255-vector
  (comp v/hex-resource (partial str "vectors/ristretto255/")))

(def ristretto255-vectors
  (comp v/hex-resources (partial str "vectors/ristretto255/")))

(def identity-point (ristretto255-vector "identity-point"))
(def basepoint (ristretto255-vector "basepoint"))
(def multiples-of-basepoint (ristretto255-vectors "multiples-of-basepoint"))

(defn int->scalar-le
  [n]
  (byte-array s/scalarbytes
              (reverse (u/n->bytes s/scalarbytes n))))

(def scalar-1
  "The number 1, as a Ristretto255 scalar."
  (int->scalar-le 1))

(deftest scalarmult-tests
  (testing "-to-buf! and regular API work identically"
    (let [q (bb/alloc s/bytes)
          r (s/scalarmult scalar-1)]
      (s/scalarmult-to-buf! q (bb/->indirect-byte-buf scalar-1))
      (is (bb/bytes= r q))))
  (testing "base point mult uses the base point"
    (is (bb/bytes=
         (s/scalarmult scalar-1)
         (s/scalarmult scalar-1 basepoint)))))

(deftest scalarmult-vector-test
  (loop [[target & the-rest] multiples-of-basepoint
         i 2]
    (let [n (int->scalar-le i)
          p (s/scalarmult n)
          p2 (s/scalarmult n basepoint)]
      (is (bb/bytes= target p))
      (is (bb/bytes= target p2)))
    (when (seq the-rest)
      (recur the-rest (inc i)))))

