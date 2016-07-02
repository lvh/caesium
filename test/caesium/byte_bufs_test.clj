(ns caesium.byte-bufs-test
  (:require [caesium.byte-bufs :as bb]
            [clojure.test :refer [deftest is]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [com.gfredericks.test.chuck.clojure-test :refer [for-all]]
            [com.gfredericks.test.chuck.properties :as prop'])
  (:import (java.nio ByteBuffer)))

(def ways-of-getting-a-buf-of-len-n
  [byte-array
   (fn [n] (ByteBuffer/allocate n))
   (fn [n] (ByteBuffer/allocateDirect n))
   (fn [n] (ByteBuffer/wrap (byte-array n)))])

(defspec ->indirect-byte-buf-spec
  1000
  (for-all
   [n gen/pos-int
    g (gen/elements ways-of-getting-a-buf-of-len-n)
    :let [src (g n)
          buf (bb/->indirect-byte-buf src)]]
   (is (= n (bb/buflen src) (bb/buflen buf)))
   (is (instance? ByteBuffer buf))
   (when-not (instance? ByteBuffer src)
     ;; when the input is a byte buffer, don't convert
     (is (not (.isDirect buf))))))

(defspec ->direct-byte-buf-spec
  1000
  (for-all
   [n gen/pos-int
    g (gen/elements ways-of-getting-a-buf-of-len-n)
    :let [src (g n)
          buf (bb/->direct-byte-buf src)]]
   (is (= n (bb/buflen src) (bb/buflen buf)))
   (is (instance? ByteBuffer buf))
   (when-not (instance? ByteBuffer src)
     ;; when the input is a byte buffer, don't convert
     (is (.isDirect buf)))))

(defspec buflen-spec
  1000
  (prop'/for-all
   [n gen/pos-int
    g (gen/elements ways-of-getting-a-buf-of-len-n)]
   (= n (bb/buflen (g n)))))

(defspec slice-buflen-spec
  1000
  (prop'/for-all
   [n gen/pos-int
    start (gen/choose 0 n)
    end (gen/choose start n)
    g (gen/elements ways-of-getting-a-buf-of-len-n)]
   (= n (bb/buflen (g n)))))

(defspec wrapped-array-buflen-spec
  1000
  (prop'/for-all
   [n gen/pos-int
    start (gen/choose 0 n)
    slicelen (gen/choose 0 (- n start))]
   (= slicelen
      (-> (byte-array n)
          (ByteBuffer/wrap start slicelen)
          (bb/buflen)))))
