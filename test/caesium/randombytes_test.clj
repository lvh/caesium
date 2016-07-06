(ns caesium.randombytes-test
  (:require [caesium.randombytes :as r]
            [clojure.test :refer [deftest is]]
            [caesium.byte-bufs :as bb])
  (:import (java.nio ByteBuffer)))

(deftest randombytes-tests
  (let [some-bytes (r/randombytes 10)]
    (is (= 10 (bb/buflen some-bytes)))))

(deftest random-to-byte-array!
  (let [some-bytes (byte-array 20)]
    (r/random-to-byte-array! some-bytes 10)
    (let [s (seq some-bytes)
          head (take 10 s)
          tail (drop 10 s)]
      (is (not= (repeat 10 0) head))
      (is (= (repeat 10 0) tail)))))

(deftest random-to-byte-buffer!
  (let [some-bytes (ByteBuffer/allocate 20)]
    (r/random-to-byte-buffer! some-bytes 10)
    (let [s (seq (bb/->bytes some-bytes))
          head (take 10 s)
          tail (drop 10 s)]
      (is (not= (repeat 10 0) head))
      (is (= (repeat 10 0) tail)))))
