(ns caesium.magicnonce.secretbox-test
  (:require [caesium.magicnonce.secretbox :as ms]
            [caesium.crypto.secretbox :as s]
            [caesium.crypto.secretbox-test :as st]
            [clojure.test :refer [deftest is]]
            [caesium.util :as u]))

(deftest xor-test
  (let [one (byte-array [1 0 1])
        two (byte-array [0 1 0])
        out (byte-array [0 0 0])]
    (is (identical? (#'ms/xor! out one two) out))
    (is (u/array-eq (byte-array [1 1 1]) out)))
  (let [one (byte-array [1 0 1])
        two (byte-array [0 1 0])]
    (is (identical? (#'ms/xor-inplace! one two) one))
    (is (u/array-eq (byte-array [1 1 1]) one))))

(deftest secretbox-pfx-test
  (let [nonce (byte-array (range s/noncebytes))
        ctext (ms/secretbox-pfx st/ptext nonce st/secret-key)]
    (is (= (+ s/noncebytes
              (alength ^bytes st/ptext)
              s/macbytes)
           (alength ^bytes ctext)))
    (is (= (range s/noncebytes)
           (take s/noncebytes ctext)))))
