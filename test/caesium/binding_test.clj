(ns caesium.binding-test
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]
            [clojure.test :refer [deftest is are]])
  (:import [caesium.binding Sodium]
           [java.lang.annotation Annotation]
           [java.lang.reflect Method Type AnnotatedElement]
           [jnr.ffi.annotations In Out Pinned LongLong]
           [jnr.ffi.byref LongLongByReference]
           [java.nio ByteBuffer]
           [jnr.ffi.types size_t]))

(deftest library-not-installed-test
  (let [result (try (#'b/load-sodium "notsodium-801a67af") (catch Throwable t t))]
    (is (= (type result) (type (UnsatisfiedLinkError.))))))

(deftest permuted-byte-types-test
  (is (= '[[^long ^{size_t {}} crypto_secretbox_keybytes []]]
         (#'b/permuted-byte-types
          '[^long ^{size_t {}} crypto_secretbox_keybytes []])))
  (is (= (let [b 'bytes
               l 'long
               B 'java.nio.ByteBuffer]
           [[b b l b b]
            [b b l b B]
            [b b l B b]
            [b b l B B]
            [b B l b b]
            [b B l b B]
            [b B l B b]
            [b B l B B]
            [B b l b b]
            [B b l b B]
            [B b l B b]
            [B b l B B]
            [B B l b b]
            [B B l b B]
            [B B l B b]
            [B B l B B]])
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
  "Given some annotation instances, return the set of their types."
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
  (let [void-fns
        #{"crypto_core_ristretto255_random"
          "crypto_core_ristretto255_scalar_add"
          "crypto_core_ristretto255_scalar_complement"
          "crypto_core_ristretto255_scalar_mul"
          "crypto_core_ristretto255_scalar_negate"
          "crypto_core_ristretto255_scalar_random"
          "crypto_core_ristretto255_scalar_reduce"
          "crypto_core_ristretto255_scalar_sub"
          "crypto_kdf_keygen"
          "crypto_shorthash_keygen"
          "randombytes"}]
    (is (= (if (void-fns (.getName method))
             Void/TYPE
             Integer/TYPE)
           (.getGenericReturnType method))))
  (doseq [{:keys [type annotations]} params]
    (is (= (condp = type
             ByteArray #{Pinned}
             ByteBuffer #{Pinned}
             Long/TYPE  #{LongLong}
             LongLongByReference #{})
           annotations))))

(defn int-func?
  "checks if given fn is supposed to have an int return type"
  [f]
  (let [fns  #{"sodium_init" "crypto_pwhash_argon2i_alg_argon2i13"
               "crypto_pwhash_alg_default" "crypto_pwhash_alg_argon2i13"
               "crypto_pwhash_alg_argon2id13" "crypto_pwhash_argon2id_alg_argon2id13"}]
    (fns f)))

(defn check-const-method
  "Check a method binding a const fn."
  [^Method method]
  (let [rtype (.getGenericReturnType method)]
    (condp = rtype
      Integer/TYPE (is (int-func? (.getName method)))
      Long/TYPE (is (= #{size_t} (clean-annotations (.getAnnotations method))))
      (is (= String rtype)))))

(defmacro with-ns
  [ns & body]
  `(let [old-ns# *ns*
         result# (volatile! nil)]
     (try
       (in-ns ~ns)
       (vreset! result# ~@body)
       (finally
         (in-ns (ns-name old-ns#))
         @result#))))

(def buf-tag
  {:tag 'java.nio.ByteBuffer})

(deftest call!-test
  (are [ns expr expected-form expected-metas]
       (with-ns ns
         (let [[_ _ & args :as expanded] (macroexpand-1 expr)]
           (and (is (= expected-form expanded))
                (is (= expected-metas (map meta args))))))
    'caesium.crypto.box
    '(caesium.binding/call! keypair sk pk)
    `(.crypto_box_keypair b/sodium ~'pk ~'sk)
    [buf-tag buf-tag]

    'caesium.crypto.box
    '(caesium.binding/call! open-easy m c n pk sk)
    `(.crypto_box_open_easy
      b/sodium ~'m ~'c (long (bb/buflen ~'c)) ~'n ~'pk ~'sk)
    [buf-tag buf-tag nil buf-tag buf-tag buf-tag]

    'caesium.crypto.generichash
    '(caesium.binding/call! generichash buf msg key)
    `(.crypto_generichash
      b/sodium
      ~'buf (long (bb/buflen ~'buf))
      ~'msg (long (bb/buflen ~'msg))
      ~'key (long (bb/buflen ~'key)))
    [buf-tag nil buf-tag nil buf-tag nil]

    'caesium.crypto.scalarmult
    '(caesium.binding/call! scalarmult q n p)
    `(.crypto_scalarmult b/sodium ~'q ~'n ~'p)
    [buf-tag buf-tag buf-tag]

    'caesium.crypto.scalarmult
    '(caesium.binding/call! scalarmult-base q n)
    `(.crypto_scalarmult_base b/sodium ~'q ~'n)
    [buf-tag buf-tag]

    'caesium.crypto.sign
    '(caesium.binding/call! sign-open m sm pk)
    `(.crypto_sign_open
      b/sodium
      ~'m nil
      ~'sm (long (bb/buflen ~'sm))
      ~'pk)
    [buf-tag nil buf-tag nil buf-tag]))
