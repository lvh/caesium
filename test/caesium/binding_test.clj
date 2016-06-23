(ns caesium.binding-test
  (:require [caesium.binding :as b]
            [clojure.test :refer [deftest is]]))

(deftest permuted-byte-types-test
  (is (= '[[^long ^{size_t {}} crypto_secretbox_keybytes []]]
         (#'b/permuted-byte-types
          '[^long ^{size_t {}} crypto_secretbox_keybytes []]))))
