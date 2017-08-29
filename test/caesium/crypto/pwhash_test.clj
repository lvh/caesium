(ns caesium.crypto.pwhash-test
  (:require [caesium.crypto.pwhash :as p]
            [caesium.byte-bufs :as bb]
            [caesium.test-utils :refer [const-test]]
            [caesium.vectors :as v]
            [caesium.util :as u]
            [caesium.randombytes :as r]
            [clojure.test :refer [are deftest is]]))


(const-test
 p/alg-argon2i13 1
 p/alg-default 1
 p/bytes-min 16
 p/bytes-max 4294967295
 p/passwd-min 0
 p/passwd-max 4294967295
 p/saltbytes 16
 p/strbytes 128
 p/strprefix "$argon2i$"
 p/opslimit-min 3
 p/opslimit-max 4294967295
 p/memlimit-min 8192
 p/opslimit-interactive 4
 p/memlimit-interactive  33554432
 p/opslimit-moderate 6
 p/memlimit-moderate 134217728
 p/opslimit-sensitive 8
 p/memlimit-sensitive 536870912

 p/argon2i-alg-argon2i13 1
 p/argon2i-bytes-min 16
 p/argon2i-bytes-max 4294967295
 p/argon2i-passwd-min 0
 p/argon2i-passwd-max 4294967295
 p/argon2i-saltbytes 16
 p/argon2i-strbytes 128
 p/argon2i-strprefix "$argon2i$"
 p/argon2i-opslimit-min 3
 p/argon2i-opslimit-max 4294967295
 p/argon2i-memlimit-min 8192
 p/argon2i-opslimit-interactive 4
 p/argon2i-memlimit-interactive  33554432
 p/argon2i-opslimit-moderate 6
 p/argon2i-memlimit-moderate 134217728
 p/argon2i-opslimit-sensitive 8
 p/argon2i-memlimit-sensitive 536870912)

(deftest pwhash-alg-default-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810" (u/hexify (p/pwhash 32 "password" salt p/opslimit-min p/memlimit-interactive p/alg-default))))))

(deftest pwhash-alg-argon2i-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810" (u/hexify (p/pwhash 32 "password" salt p/opslimit-min p/memlimit-interactive p/alg-argon2i13))))))


(deftest pwhash-argon2i-alg-argon2i13-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810" (u/hexify (p/pwhash-argon2i 32 "password" salt p/argon2i-opslimit-min p/argon2i-memlimit-interactive p/argon2i-alg-argon2i13))))))

(deftest pwhash-str-and-verify-test
  []
  (let [hashpass (p/pwhash-str "password" p/opslimit-min p/memlimit-interactive)]
                                        ; (println (caesium.byte-bufs/buflen (bb/->bytes hashpass)))
    (p/pwhash-str-verify hashpass "password")
    (is (= 1 0))))

;;(deftest )
;; (def blake2b-vector
;;   (comp v/hex-resource (partial str "vectors/generichash/blake2b/")))

;; (deftest generichash-kat-test
;;   (are [args expected] (bb/bytes= (apply g/hash args) expected)
;;     [(byte-array [])]
;;     (blake2b-vector "digest-empty-string-32")

;;     [(byte-array [])
;;      {:size 32}]
;;     (blake2b-vector "digest-empty-string-32")

;;     [(byte-array [])
;;      {:size 64}]
;;     (blake2b-vector "digest-empty-string-64")

;;     [(byte-array [90])
;;      {:size 64}]
;;     (blake2b-vector "digest-Z-64")))

;; (deftest hash-to-buf!-test
;;   (are [args expected] (let [out (bb/alloc g/bytes)]
;;                          (bb/bytes= (apply g/hash-to-buf! out args) expected))
;;     [(bb/alloc 0)]
;;     (blake2b-vector "digest-empty-string-32")

;;     [(bb/alloc 0) {:key (bb/alloc 0)}]
;;     (blake2b-vector "digest-empty-string-32")))

;; (deftest blake2b-kat-test
;;   (are [args expected] (bb/bytes= (apply g/blake2b args) expected)
;;     [(byte-array [])]
;;     (blake2b-vector "digest-empty-string-32")

;;     [(byte-array [])
;;      {:size 32}]
;;     (blake2b-vector "digest-empty-string-32")

;;     [(byte-array [])
;;      {:size 64}]
;;     (blake2b-vector "digest-empty-string-64")

;;     [(byte-array [90])
;;      {:size 64}]
;;     (blake2b-vector "digest-Z-64")

;;     [(.getBytes "The quick brown fox jumps over the lazy dog")
;;      {:key (.getBytes "This is a super secret key. Ssshh!")
;;       :salt (.getBytes "0123456789abcdef")
;;       :personal (.getBytes "fedcba9876543210")}]
;;     (blake2b-vector "digest-with-key-salt-personal-32")

;;     [(.getBytes "The quick brown fox jumps over the lazy dog")
;;      {:size 32
;;       :key (.getBytes "This is a super secret key. Ssshh!")
;;       :salt (.getBytes "0123456789abcdef")
;;       :personal (.getBytes "fedcba9876543210")}]
;;     (blake2b-vector "digest-with-key-salt-personal-32")

;;     [(.getBytes "The quick brown fox jumps over the lazy dog")
;;      {:size 64
;;       :key (.getBytes "This is a super secret key. Ssshh!")
;;       :salt (.getBytes "0123456789abcdef")
;;       :personal (.getBytes "fedcba9876543210")}]
;;     (blake2b-vector "digest-with-key-salt-personal-64")))

;; (def blake2b-empty-args-variations
;;   "All of the different ways you could spell that you want the digest
;;   of the empty string: with or without key, salt, and
;;   personalization.

;;   When given to the blake2b function, all of these should return the
;;   empty string digest."
;;   (for [key-expr [nil {:key (byte-array 0)}]
;;         salt-expr [nil {:salt (byte-array 16)}]
;;         personal-expr [nil {:personal (byte-array 16)}]]
;;     [(byte-array 0) (merge key-expr salt-expr personal-expr)]))

;; (deftest blake2b-empty-args-variations-tests
;;   (doseq [args blake2b-empty-args-variations]
;;     (is (bb/bytes= (apply g/blake2b args)
;;                    (blake2b-vector "digest-empty-string-32"))
;;         (str "args: " args))))
