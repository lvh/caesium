(ns caesium.magicnonce.secretbox-benchmark
  (:require [caesium.randombytes :refer [randombytes]]
            [caesium.magicnonce.secretbox :as ms]
            [caesium.bench-utils :refer [fmt-bytes print-title]]
            [clojure.test :refer [deftest]]
            [criterium.core :refer [bench quick-bench]]))

(deftest ^:benchmark synthetic-nonce-benchmarks
  (let [f @#'ms/synthetic-nonce
        key (randombytes ms/keybytes)
        sizes (map (partial bit-shift-left 1) [6 8 10 12 20 24])]
    (doseq [[size message] (map (juxt identity randombytes) sizes)]
      (print-title "synthetic nonce generation" (fmt-bytes size))
      (quick-bench (f message key)))))

(deftest ^:benchmark implicit-nonce-benchmarks
  (let [key (randombytes ms/keybytes)
        sizes (map (partial bit-shift-left 1) [6 8 10 12 20 24])]
    (doseq [[size message] (map (juxt identity randombytes) sizes)
            f [ms/secretbox-nmr ms/secretbox-rnd ms/secretbox-det]]
      (print-title "implicit nonce scheme" f (fmt-bytes size))
      (bench (f message key)))))
