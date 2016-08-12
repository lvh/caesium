(ns caesium.crypto.scalarmult-test
  (:require [caesium.crypto.scalarmult :as s]
            [caesium.test-utils :refer [const-test]]
            [caesium.util :as u]
            [clojure.test :refer [are deftest is testing]]))

(const-test
 s/bytes 32
 s/scalarbytes 32
 s/primitive "curve25519")

(def basepoint
  (byte-array (into [9] (repeat (dec s/bytes) 0))))

(def scalar-1
  "The number 1, as a curve25519 scalar."
  (s/int->scalar 1))

(deftest scalarmult-tests
  (testing "-to-buf! and regular API work identically"
    (let [q (byte-array s/bytes)
          r (s/scalarmult scalar-1)]
      (s/scalarmult-to-buf! scalar-1 q)
      (is (u/array-eq r q))))
  (testing "base point mult uses the base point"
    (is (u/array-eq
         (s/scalarmult scalar-1)
         (s/scalarmult scalar-1 basepoint)))))

(deftest int->scalar-test
  (are [n expected] (u/array-eq expected (s/int->scalar n))
    0 (byte-array 32)
    0M (byte-array 32)
    1000000000000 (byte-array (into (vec (repeat 27 0))
                                    [-24 -44 -91 16 0]))))
