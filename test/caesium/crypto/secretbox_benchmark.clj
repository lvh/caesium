(ns caesium.crypto.secretbox-benchmark
  (:require [caesium.randombytes :refer [randombytes]]
            [caesium.crypto.secretbox :as s]
            [caesium.bytes-conv :as bc]
            [clojure.test :refer [deftest]]
            [criterium.core :refer [bench]]
            [caesium.bench-utils :refer [fmt-bytes]])
  (:import [java.nio ByteBuffer]))

;; secretbox to-buf! macros vs fn vs no casts with indirect byte bufs

(deftest ^:benchmark to-buf!-benchmarks
  (let [key (randombytes s/keybytes)
        sizes (map (partial bit-shift-left 1) [6 8 10 12 20 24])]
    (println "secretbox to-buf! macros vs fn vs no casts with direct bufs")
    (println "these bufs already exist, so there is no allocation")
    (doseq [[size message] (map (juxt identity randombytes) sizes)
            f [s/secretbox-easy-to-direct-byte-bufs-with-macros!
               s/secretbox-easy-to-direct-byte-bufs!
               s/secretbox-easy-to-byte-bufs-nocast!]]
      (println f (fmt-bytes size))
      (let [nonce (bc/->direct-byte-buf (randombytes s/noncebytes))
            out (ByteBuffer/allocateDirect (+ s/macbytes size))]
        (bench (f out message nonce key))))

    (println "secretbox to-buf! macros vs fn vs no casts with indirect bufs")
    (println "these bufs already exist, so there is no allocation")
    (doseq [[size message] (map (juxt identity randombytes) sizes)
            f [s/secretbox-easy-to-indirect-byte-bufs-with-macros!
               s/secretbox-easy-to-indirect-byte-bufs!
               s/secretbox-easy-to-byte-bufs-nocast!]]
      (println f (fmt-bytes size))
      (let [nonce (bc/->indirect-byte-buf (randombytes s/noncebytes))
            out (ByteBuffer/allocate (+ s/macbytes size))]
        (bench (f out message nonce key))))))
