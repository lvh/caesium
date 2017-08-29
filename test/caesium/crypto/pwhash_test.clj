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
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810"
           (u/hexify
            (p/pwhash 32 "password" salt p/opslimit-min p/memlimit-interactive p/alg-default))))))

(deftest pwhash-alg-argon2i-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810"
           (u/hexify (p/pwhash 32 "password" salt p/opslimit-min p/memlimit-interactive p/alg-argon2i13))))))

(deftest pwhash-argon2i-alg-argon2i13-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810"
           (u/hexify (p/pwhash-argon2i 32 "password" salt p/argon2i-opslimit-min p/argon2i-memlimit-interactive p/argon2i-alg-argon2i13))))))

(deftest pwhash-str-and-verify-test
  []
  (let [hashpass (p/pwhash-str "password" p/opslimit-min p/memlimit-interactive)]
    (p/pwhash-str-verify hashpass "password")))
