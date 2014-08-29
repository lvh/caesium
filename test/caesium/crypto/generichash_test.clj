(ns caesium.crypto.generichash-test
  (:require [caesium.crypto.generichash :refer :all]
            [caesium.crypto.util :refer [unhexify array-eq]]
            [clojure.test :refer :all]))

(deftest blake2b-kat-test
  (testing "blake2b works directly"
    (are [args expected] (array-eq (apply blake2b args)
                                   expected)
        [(byte-array [])] (unhexify "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
        [(byte-array [90])] (unhexify "4884256d056fb76f83f10ab85c127682d447d126d99dee526883488f57951fffb576a16d8a7fd391420e23b7c0cf14b413878de095dc3d84bcaecba0bc657c77")
        [(.getBytes "The quick brown fox jumps over the lazy dog")
         {:key (.getBytes "This is a super secret key. Ssshh!")
          :salt (.getBytes "0123456789abcdef")
          :personal (.getBytes "fedcba9876543210")}]
        (unhexify "9479874d504f0447d43d72a969c989c34032172276ac50077e0027277c3c8d867bee9ee314c8506e4e4a9b3030b989d3eb7b4c1826c8e0d56e6aa71b1d4cf388"))))
