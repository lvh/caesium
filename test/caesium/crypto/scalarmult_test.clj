(ns caesium.crypto.scalarmult-test
  (:require [caesium.crypto.scalarmult :as s]
            [clojure.test :refer [deftest is are]]
            [caesium.util :as u]))

(deftest consts-tests
  (is (= 32 s/bytes))
  (is (= 32 s/scalarbytes))
  (is (= "curve25519" s/primitive)))
(deftest int->scalar-test
  (are [n expected] (u/array-eq expected (s/int->scalar n))
    0 (byte-array 32)
    0M (byte-array 32)
    1000000000000 (byte-array (into (vec (repeat 27 0))
                                    [-24 -44 -91 16 0]))))
