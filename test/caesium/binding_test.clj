(ns caesium.binding-test
  (:require [caesium.binding :as b]
            [clojure.test :refer [deftest is]]
            [taoensso.timbre :refer [info spy]])
  (:import [caesium.binding Sodium]
           [java.lang.annotation Annotation]
           [java.lang.reflect Method Parameter Type]
           [jnr.ffi.annotations In Out Pinned LongLong]
           [jnr.ffi.byref LongLongByReference]
           [java.nio ByteBuffer]
           [jnr.ffi.types size_t]))

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

(def ByteArray (Class/forName "[B"))

(declare check-method check-const-method)

(deftest interface-test
  (doseq [method (.getMethods Sodium)]
    (if-let [params (seq (.getParameters ^Method method))]
      (check-method method params)
      (check-const-method method))))

(defn check-method
  "Check a method binding a non-const fn."
  [^Method method params]
  (is (= (if (= "randombytes" (.getName method))
           Void/TYPE
           Integer/TYPE)
         (.getGenericReturnType method)))
  (doseq [param params]
    (let [param-type (.getParameterizedType ^Parameter param)
          annotation-types (->> (.getAnnotations ^Parameter param)
                                (map #(.annotationType ^Annotation %))
                                set)]
      (condp (fn [x y] (x y)) param-type
        #{ByteArray ByteBuffer} (is (= #{Pinned} annotation-types))
        #{Long/TYPE} (is (= #{size_t} annotation-types))
        #{LongLongByReference} (is (= #{} annotation-types))))))

(defn check-const-method
  "Check a method binding a const fn."
  [^Method method]
  (let [rtype (.getGenericReturnType method)]
    ))
