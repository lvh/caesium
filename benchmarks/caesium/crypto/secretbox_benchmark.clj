(ns caesium.crypto.secretbox-benchmark
  (:require [caesium
             [bench-utils :refer [fmt-bytes print-title]]
             [binding :refer [sodium]]
             [byte-bufs :as bb]
             [randombytes :refer [randombytes]]]
            [byte-streams :as bs]
            [caesium.crypto.secretbox :as s]
            [clojure.test :refer [deftest]]
            [criterium.core :refer [bench]])
  (:import java.nio.ByteBuffer))

(defmacro ->indirect-byte-buf-macro
  [x]
  `(bs/convert ~x ByteBuffer {:direct? false}))

(defmacro ->direct-byte-buf-macro
  [x]
  `(bs/convert ~x ByteBuffer {:direct? true}))

(defn secretbox-easy-to-direct-byte-bufs-with-macros!
  [out msg nonce key]
  (let [^ByteBuffer out (->direct-byte-buf-macro out)
        ^ByteBuffer msg (->direct-byte-buf-macro msg)
        ^ByteBuffer nonce (->direct-byte-buf-macro nonce)
        ^ByteBuffer key (->direct-byte-buf-macro key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-direct-byte-bufs!
  [out msg nonce key]
  (let [out (bb/->direct-byte-buf out)
        msg (bb/->direct-byte-buf msg)
        nonce (bb/->direct-byte-buf nonce)
        key (bb/->direct-byte-buf key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-indirect-byte-bufs-with-macros!
  [out msg nonce key]
  (let [^ByteBuffer out (->indirect-byte-buf-macro out)
        ^ByteBuffer msg (->indirect-byte-buf-macro msg)
        ^ByteBuffer nonce (->indirect-byte-buf-macro  nonce)
        ^ByteBuffer key (->indirect-byte-buf-macro  key)]
    (.crypto_secretbox_easy sodium out msg (.remaining msg) nonce key)
    out))

(defn secretbox-easy-to-indirect-byte-bufs!
  [out msg nonce key]
  (let [out (bb/->indirect-byte-buf out)
        msg (bb/->indirect-byte-buf msg)
        nonce (bb/->indirect-byte-buf nonce)
        key (bb/->indirect-byte-buf key)]
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
  [prefix fs converter]
  (let [rand-buf `(comp ~converter ~randombytes)]
    `(doseq [[size# ptext#] (map (juxt identity ~rand-buf) sizes)
             f# ~fs]
       (let [key# (~rand-buf s/keybytes)
             nonce# (~rand-buf s/noncebytes)
             out# (~rand-buf (+ s/macbytes size#))]
         (print-title ~prefix
                      f#
                      (fmt-bytes size#)
                      (mapv type [out# ptext# nonce# key#]))
         (bench (f# out# ptext# nonce# key#))))))

(deftest ^:benchmark to-buf!-benchmarks
  (bench-secretnonce
   "secretbox to-buf! with direct bufs, pre-allocation"
   [secretbox-easy-to-direct-byte-bufs-with-macros!
    secretbox-easy-to-direct-byte-bufs!
    secretbox-easy-to-byte-bufs-nocast!
    secretbox-easy-refl!]
   bb/->direct-byte-buf)

  (bench-secretnonce
   "secretbox to-buf! with indirect bufs, pre-allocation"
   [secretbox-easy-to-indirect-byte-bufs-with-macros!
    secretbox-easy-to-indirect-byte-bufs!
    secretbox-easy-to-byte-bufs-nocast!
    secretbox-easy-refl!]
   bb/->indirect-byte-buf)

  (bench-secretnonce
   "secretbox to-buf! with byte arrays, pre-allocation"
   [s/secretbox-easy-to-buf!]
   identity))
