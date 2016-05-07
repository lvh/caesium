(ns caesium.crypto.scalarmult-test
  (:require [caesium.crypto.scalarmult :as s]
            [clojure.test :refer [deftest is are testing]]
            [caesium.util :as u]))

(deftest consts-tests
  (is (= 32 s/bytes))
  (is (= 32 s/scalarbytes))
  (is (= "curve25519" s/primitive)))

(def basepoint
  (byte-array (into [9] (repeat (dec s/bytes) 0))))

(def scalar-1
  "The number 1, as a curve25519 scalar."
  (s/int->scalar 1))

(deftest scalarmult-tests
  (testing "-to-buf! and regular API work identically"
    (let [out (byte-array s/bytes)
          r (s/scalarmult scalar-1)]
      (s/scalarmult-to-buf! scalar-1 out)
      (is (u/array-eq r out))))
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
