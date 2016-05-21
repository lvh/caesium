(ns caesium.magicnonce.secretbox-test
  (:require [caesium.magicnonce.secretbox :as s]
            [clojure.test :refer [deftest is]]
            [caesium.util :as u]))

(deftest xor-test
  (let [one (byte-array [1 0 1])
        two (byte-array [0 1 0])
        out (byte-array [0 0 0])]
    (is (identical? (#'s/xor! out one two) out))
    (is (u/array-eq (byte-array [1 1 1]) out)))
  (let [one (byte-array [1 0 1])
        two (byte-array [0 1 0])]
    (is (identical? (#'s/xor-inplace! one two) one))
    (is (u/array-eq (byte-array [1 1 1]) one))))
