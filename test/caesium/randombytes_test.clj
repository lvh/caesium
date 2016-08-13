(ns caesium.randombytes-test
  (:require [caesium.randombytes :as r]
            [clojure.test :refer [deftest is]]
            [caesium.byte-bufs :as bb])
  (:import (java.nio ByteBuffer)))

(deftest randombytes-test
  (let [buf (r/randombytes 10)]
    (is (= 10 (bb/buflen buf)))))

(deftest random-to-buf!-test
  (let [buf (bb/alloc 30)]
    (is (= #{0} (set (seq (bb/->bytes buf)))))
    (r/random-to-buf! buf)
    (is (not= #{0} (set (seq (bb/->bytes buf))))))
  (let [buf (bb/alloc 20)]
    (r/random-to-buf! buf 10)
    (let [s (seq (bb/->bytes buf))
          head (take 10 s)
          tail (drop 10 s)]
      (is (not= (repeat 10 0) head))
      (is (= (repeat 10 0) tail)))))
