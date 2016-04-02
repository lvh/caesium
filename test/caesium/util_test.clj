(ns caesium.util-test
  (:require
   [caesium.util :as u]
   [clojure.test :refer :all]))

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

(deftest hexify-text
  (testing "hexify works"
    (are [hex raw] (= hex (u/hexify (byte-array raw)))
      "" []
      "01" [1]
      "02" [2]
      "ff" [-1]
      "010203" [1 2 3])))
