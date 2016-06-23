(ns caesium.magicnonce.secretbox-benchmark
  (:require [caesium.randombytes :refer [randombytes]]
            [caesium.magicnonce.secretbox :as ms]
            [caesium.bench-utils :refer [fmt-bytes]]
            [clojure.test :refer [deftest]]
            [criterium.core :refer [bench]]))

(deftest ^:benchmark implicit-nonce-benchmarks
  (let [key (randombytes ms/keybytes)
        sizes (map (partial bit-shift-left 1) [6 8 10 12 20 24])]
    (println "implicit nonce schemes")
    (doseq [[size message] (map (juxt identity randombytes) sizes)
            f [ms/secretbox-nmr ms/secretbox-rnd ms/secretbox-det]]
      (println f (fmt-bytes size))
      (bench (f message key)))))
