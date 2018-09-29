(ns caesium.crypto.shorthash-test
  (:require [caesium.crypto.shorthash :as sh]
            [clojure.test :refer [is testing deftest]]
            [caesium.test-utils :refer [const-test]]
            [caesium.byte-bufs :as bb]
            [caesium.vectors :as v]))

(const-test
 sh/keybytes 16
 sh/bytes 8
 sh/primitive "siphash24")

(def max-len 64)

(def shorthash-vectors (v/hex-resources "vectors/shorthash/shorthash.txt"))

(deftest shorthash-kat-test
  "Tests and test vectors from:
  https://github.com/jedisct1/libsodium/blob/master/test/default/shorthash.c
  https://github.com/jedisct1/libsodium/blob/master/test/default/shorthash.exp"
  (let [k (->> (iterate inc 0)
               (take sh/keybytes)
               (byte-array))
        full-range (range 64)
        test-vals (for [r full-range]
                    (->> full-range
                         (take r)
                         (byte-array)))
        test-answers (map #(sh/shorthash % k) test-vals)]
    (dorun (map (fn [x y]
                  (is (bb/bytes= x y)))
                test-answers
                shorthash-vectors))))

(deftest keygen!-test
  (let [[f & rs] (repeatedly 10 sh/keygen!)]
    (doseq [r rs]
      (is (not (bb/bytes= f r))))))
