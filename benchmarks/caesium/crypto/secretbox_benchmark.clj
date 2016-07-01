(ns caesium.crypto.secretbox-benchmark
  (:require [caesium.randombytes :refer [randombytes]]
            [caesium.crypto.secretbox :as s]
            [caesium.bytes-conv :as bc]
            [clojure.test :refer [deftest]]
            [criterium.core :refer [bench]]
            [caesium.bench-utils :refer [fmt-bytes]])
  (:import [java.nio ByteBuffer]))

(def sizes (map (partial bit-shift-left 1) [6 8 10 12 20 24]))

(defmacro bench-secretnonce
  [fs converter]
  (let [rand-buf `(comp ~converter ~randombytes)]
    `(doseq [[size# msg#] (map (juxt identity ~rand-buf) sizes)
             f# ~fs]
       (let [key# (~rand-buf s/keybytes)
             nonce# (~rand-buf s/noncebytes)
             out# (~rand-buf (+ s/macbytes size#))]
         (println f# (fmt-bytes size#) (mapv type [out# msg# nonce# key#]))
         (bench (f out# msg# nonce# key#))))))

(deftest ^:benchmark to-buf!-benchmarks
  (println "secretbox to-buf! with direct bufs, pre-allocation")
  (bench-secretnonce [s/secretbox-easy-to-direct-byte-bufs-with-macros!
                      s/secretbox-easy-to-direct-byte-bufs!
                      s/secretbox-easy-to-byte-bufs-nocast!
                      s/secretbox-easy-refl!]
                     bc/->direct-byte-buf)

  (println "secretbox to-buf! with indirect bufs, pre-allocation")
  (bench-secretnonce [s/secretbox-easy-to-indirect-byte-bufs-with-macros!
                      s/secretbox-easy-to-indirect-byte-bufs!
                      s/secretbox-easy-to-byte-bufs-nocast!
                      s/secretbox-easy-refl!]
                     bc/->indirect-byte-buf)

  (println "secretbox to-buf! with byte arrays, pre-allocation")
  (bench-secretnonce [s/secretbox-easy-to-buf!] identity))
