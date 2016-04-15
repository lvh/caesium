(ns caesium.randombytes-test
  (:require [caesium.randombytes :as r]
            [clojure.test :refer [deftest is]]))

(deftest randombytes-tests
  (let [some-bytes (r/randombytes 10)]
    (is (= 10 (alength some-bytes)))))
