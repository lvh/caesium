(ns caesium.crypto.secretbox-benchmark
  (:require [caesium.randombytes :refer [randombytes]]
            [caesium.crypto.secretbox :as s]
            [caesium.bytes-conv :as bc]
            [clojure.test :refer [deftest]]
            [criterium.core :refer [bench]]
            [caesium.bench-utils :refer [fmt-bytes]]
            [caesium.binding :refer [sodium]])
  (:import [java.nio ByteBuffer]))

(defn secretbox-easy-to-direct-byte-bufs-with-macros!
  [out msg nonce key]
  (let [^ByteBuffer out (bc/->direct-byte-buf-macro out)
        ^ByteBuffer msg (bc/->direct-byte-buf-macro msg)
        ^ByteBuffer nonce (bc/->direct-byte-buf-macro nonce)
        ^ByteBuffer key (bc/->direct-byte-buf-macro key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-direct-byte-bufs!
  [out msg nonce key]
  (let [^ByteBuffer out (bc/->direct-byte-buf out)
        ^ByteBuffer msg (bc/->direct-byte-buf msg)
        ^ByteBuffer nonce (bc/->direct-byte-buf nonce)
        ^ByteBuffer key (bc/->direct-byte-buf key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-indirect-byte-bufs-with-macros!
  [out msg nonce key]
  (let [^ByteBuffer out (bc/->indirect-byte-buf-macro out)
        ^ByteBuffer msg (bc/->indirect-byte-buf-macro msg)
        ^ByteBuffer nonce (bc/->indirect-byte-buf-macro nonce)
        ^ByteBuffer key (bc/->indirect-byte-buf-macro key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-indirect-byte-bufs!
  [out msg nonce key]
  (let [^ByteBuffer out (bc/->indirect-byte-buf out)
        ^ByteBuffer msg (bc/->indirect-byte-buf msg)
        ^ByteBuffer nonce (bc/->indirect-byte-buf nonce)
        ^ByteBuffer key (bc/->indirect-byte-buf key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-byte-bufs-nocast!
  [^ByteBuffer out ^ByteBuffer msg ^ByteBuffer nonce ^ByteBuffer key]
  (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
  out)

(defn secretbox-easy-refl!
  [out msg nonce key]
  (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
  out)


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
  (bench-secretnonce [secretbox-easy-to-direct-byte-bufs-with-macros!
                      secretbox-easy-to-direct-byte-bufs!
                      secretbox-easy-to-byte-bufs-nocast!
                      secretbox-easy-refl!]
                     bc/->direct-byte-buf)

  (println "secretbox to-buf! with indirect bufs, pre-allocation")
  (bench-secretnonce [secretbox-easy-to-indirect-byte-bufs-with-macros!
                      secretbox-easy-to-indirect-byte-bufs!
                      secretbox-easy-to-byte-bufs-nocast!
                      secretbox-easy-refl!]
                     bc/->indirect-byte-buf)

  (println "secretbox to-buf! with byte arrays, pre-allocation")
  (bench-secretnonce [s/secretbox-easy-to-buf!] identity))
