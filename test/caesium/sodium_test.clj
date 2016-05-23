(ns caesium.sodium-test
  (:require [caesium.sodium :as s]
            [clojure.test :refer [deftest is]]))

(deftest init-test
  (is (#{0 1} (s/init)))
  (is (= 1 (s/init))))
