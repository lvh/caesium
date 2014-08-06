(ns caesium.crypto.hash-test
  (:require [caesium.crypto.hash :refer :all]
            [clojure.test :refer :all])
  (:import (java.util Arrays)))

(defn array-eq [a b] (Arrays/equals a b))

(defn unhexify [s]
  (let [encoded-bytes (partition 2 s)
        hex-pair->int (fn [[x y]]
                        (unchecked-byte (Integer/parseInt (str x y) 16)))
        decoded-bytes (map hex-pair->int encoded-bytes)]
    (into-array Byte/TYPE decoded-bytes)))

(deftest unhexify-test
  (testing "unhexify works"
    (are [hex raw] (= (vec (unhexify hex))
                      (vec (byte-array raw)))
         "" []
         "01" [1]
         "02" [2]
         "ff" [-1]
         "010203" [1 2 3])))

(def blake2-empty-string-image-as-hex
  "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")

(deftest blake2-test-vectors-test
  (testing "blake2 works directly"
    (are [args expected] (array-eq (apply blake2 args)
                                   expected)
        [(byte-array [])] (unhexify blake2-empty-string-image-as-hex)
        [(byte-array [90])] (unhexify "4884256d056fb76f83f10ab85c127682d447d126d99dee526883488f57951fffb576a16d8a7fd391420e23b7c0cf14b413878de095dc3d84bcaecba0bc657c77"))))
