(ns caesium.binding-test
  (:require [caesium.binding :as b]
            [clojure.test :refer [deftest is]]))

(deftest permuted-byte-types-test
  (is (= '[[^long ^{size_t {}} crypto_secretbox_keybytes []]]
         (#'b/permuted-byte-types
          '[^long ^{size_t {}} crypto_secretbox_keybytes []])))
  (is (= '[[bytes bytes long bytes bytes]
           [bytes bytes long bytes java.nio.ByteBuffer]
           [bytes bytes long java.nio.ByteBuffer bytes]
           [bytes bytes long java.nio.ByteBuffer java.nio.ByteBuffer]
           [bytes java.nio.ByteBuffer long bytes bytes]
           [bytes java.nio.ByteBuffer long bytes java.nio.ByteBuffer]
           [bytes java.nio.ByteBuffer long java.nio.ByteBuffer bytes]
           [bytes
            java.nio.ByteBuffer
            long
            java.nio.ByteBuffer
            java.nio.ByteBuffer]
           [java.nio.ByteBuffer bytes long bytes bytes]
           [java.nio.ByteBuffer bytes long bytes java.nio.ByteBuffer]
           [java.nio.ByteBuffer bytes long java.nio.ByteBuffer bytes]
           [java.nio.ByteBuffer
            bytes
            long
            java.nio.ByteBuffer
            java.nio.ByteBuffer]
           [java.nio.ByteBuffer java.nio.ByteBuffer long bytes bytes]
           [java.nio.ByteBuffer
            java.nio.ByteBuffer
            long
            bytes
            java.nio.ByteBuffer]
           [java.nio.ByteBuffer
            java.nio.ByteBuffer
            long
            java.nio.ByteBuffer
            bytes]
           [java.nio.ByteBuffer
            java.nio.ByteBuffer
            long
            java.nio.ByteBuffer
            java.nio.ByteBuffer]]
         (mapv (fn [[_ args]] (mapv (comp :tag meta) args))
              (#'b/permuted-byte-types
               '[^int crypto_secretbox_easy
                 [^bytes ^{Pinned {}} c
                  ^bytes ^{Pinned {}} m
                  ^long ^{LongLong {}} mlen
                  ^bytes ^{Pinned {}} n
                  ^bytes ^{Pinned {}} k]])))))
