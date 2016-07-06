(ns caesium.binding-test
  (:require [caesium.binding :as b]
            [clojure.test :refer [deftest is]])
  (:import [caesium.binding Sodium]
           [java.lang.annotation Annotation]
           [java.lang.reflect Method Type AnnotatedElement]
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

(defn ^:private clean-annotations
  [annotations]
  (set (map #(.annotationType ^Annotation %) annotations)))

;; These tests do not use the Parameter class anymore, because that
;; was added in JDK 8 and therefore broke the JDK 7 builder.

(deftest interface-test
  (doseq [^Method method (.getMethods Sodium)]
    (if-let [params (seq (map (fn [t as]
                                {:method method
                                 :type t
                                 :annotations (clean-annotations as)})
                              (.getParameterTypes method)
                              (.getParameterAnnotations method)))]
      (check-method method params)
      (check-const-method method))))

(defn check-method
  "Check a method binding a non-const fn."
  [^Method method params]
  (is (= (if (= "randombytes" (.getName method))
           Void/TYPE
           Integer/TYPE)
         (.getGenericReturnType method)))
  (doseq [{:keys [type annotations]} params]
    (is (= (condp (fn [x y] (x y)) type
             #{ByteArray ByteBuffer} #{Pinned}
             #{Long/TYPE}  #{LongLong}
             #{LongLongByReference} #{})
           annotations))))

(defn check-const-method
  "Check a method binding a const fn."
  [^Method method]
  (let [rtype (.getGenericReturnType method)]
    (condp = rtype
      Integer/TYPE (is (= "sodium_init" (.getName method)))
      Long/TYPE (is (= #{size_t}
                       (clean-annotations (.getAnnotations method))))
      (is (= String rtype)))))
