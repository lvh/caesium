(ns caesium.crypto.secretbox-benchmark
  (:require [caesium.randombytes :refer [randombytes]]
            [caesium.crypto.secretbox :as s]
            [clojure.test :refer [deftest]]
            [criterium.core :refer [bench]]))
