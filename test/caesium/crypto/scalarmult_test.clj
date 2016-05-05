(ns caesium.crypto.scalarmult-test
  (:require [caesium.crypto.scalarmult :as s]
            [clojure.test :refer [deftest is]]))

(deftest consts-tests
  (is (= 32 s/bytes))
  (is (= 32 s/scalarbytes))
  (is (= "curve25519" s/primitive)))
