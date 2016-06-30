(ns caesium.crypto.secretbox-benchmark
  (:require [caesium.randombytes :refer [randombytes]]
            [caesium.crypto.secretbox :as s]
            [caesium.bytes-conv :as bc]
            [clojure.test :refer [deftest]]
            [criterium.core :refer [bench]]
            [caesium.bench-utils :refer [fmt-bytes]])
  (:import [java.nio ByteBuffer]))

;; secretbox to-buf! macros vs fn vs no casts with indirect byte bufs

(def random-direct-byte-buf (comp bc/->direct-byte-buf randombytes))
(def random-indirect-byte-buf (comp bc/->indirect-byte-buf randombytes))

(deftest ^:benchmark to-buf!-benchmarks
  (let [sizes (map (partial bit-shift-left 1) [6 8 10 12 20 24])]
    (println "secretbox to-buf! with direct bufs")
    (println "these bufs already exist, so there is no allocation")
    (doseq [[size msg] (map (juxt identity random-direct-byte-buf) sizes)
            f [s/secretbox-easy-to-direct-byte-bufs-with-macros!
               s/secretbox-easy-to-direct-byte-bufs!
               s/secretbox-easy-to-byte-bufs-nocast!
               s/secretbox-easy-refl!]]
      (let [key (random-direct-byte-buf s/keybytes)
            nonce (random-direct-byte-buf s/noncebytes)
            out (ByteBuffer/allocateDirect (+ s/macbytes size))]
        (println f (fmt-bytes size) (mapv type out msg nonce key))
        (bench (f out msg nonce key))))

    (println "secretbox to-buf! with indirect bufs")
    (println "these bufs already exist, so there is no allocation")
    (doseq [[size msg] (map (juxt identity random-indirect-byte-buf) sizes)
            f [s/secretbox-easy-to-indirect-byte-bufs-with-macros!
               s/secretbox-easy-to-indirect-byte-bufs!
               s/secretbox-easy-to-byte-bufs-nocast!
               s/secretbox-easy-refl!]]
      (let [key (random-indirect-byte-buf s/keybytes)
            nonce (random-indirect-byte-buf s/noncebytes)
            out (ByteBuffer/allocate (+ s/macbytes size))]
        (println f (fmt-bytes size) (mapv type out msg nonce key))
        (bench (f out msg nonce key))))

    (println "secretbox to-buf! with byte arrays")
    (println "these bufs already exist, so there is no allocation")
    (doseq [[size msg] (map (juxt identity randombytes) sizes)
            f [s/secretbox-easy-to-buf!]]
      (let [key (randombytes s/keybytes)
            nonce (randombytes s/noncebytes)
            out (byte-array (+ s/macbytes size))]
        (println f (fmt-bytes size) (mapv type [out msg nonce key]))
        (bench (f out msg nonce key))))))
