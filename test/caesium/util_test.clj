(ns caesium.util-test
  (:require
   [caesium.util :as u]
   [clojure.test :refer [deftest testing are]]))

(deftest array-eq-test
  (testing "array equality works"
    (are [a] (u/array-eq a a)
      (byte-array [])
      (byte-array [90])))
  (testing "array inequality works"
    (are [a b] (not (u/array-eq a b))
      (byte-array []) (byte-array [90])
      (byte-array [90]) (byte-array []))))

(deftest unhexify-test
  (testing "unhexify works"
    (are [hex raw] (= raw (vec (u/unhexify hex)))
      "" []
      "01" [1]
      "02" [2]
      "ff" [-1]
      "010203" [1 2 3])))

(deftest hexify-test
  (testing "hexify works"
    (are [hex raw] (= hex (u/hexify (byte-array raw)))
      "" []
      "01" [1]
      "02" [2]
      "ff" [-1]
      "010203" [1 2 3])))

(deftest n->bytes-test
  (are [n expected] (u/array-eq expected (u/n->bytes 24 n))
    0 (byte-array 24)
    0M (byte-array 24)
    1000000000000 (byte-array (into (vec (repeat 19 0))
                                    [-24 -44 -91 16 0])))
  (are [n expected] (u/array-eq expected (u/n->bytes 16 n))
    0 (byte-array 16)
    0M (byte-array 16)
    1000000000000 (byte-array (into (vec (repeat 11 0))
                                    [-24 -44 -91 16 0]))))
