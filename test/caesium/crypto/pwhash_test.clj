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
 p/argon2i-memlimit-sensitive 536870912

 p/argon2id-alg-argon2id13 2
 p/argon2id-bytes-min 16
 p/argon2id-bytes-max 4294967295
 p/argon2id-passwd-min 0
 p/argon2id-passwd-max 4294967295
 p/argon2id-saltbytes 16
 p/argon2id-strbytes 128
 p/argon2id-strprefix "$argon2id$"
 p/argon2id-opslimit-min 1
 p/argon2id-opslimit-max 4294967295
 p/argon2id-memlimit-min 8192
 p/argon2id-opslimit-interactive 2
 p/argon2id-memlimit-interactive  67108864
 p/argon2id-opslimit-moderate 3
 p/argon2id-memlimit-moderate 268435456
 p/argon2id-opslimit-sensitive 4
 p/argon2id-memlimit-sensitive 1073741824

 p/scryptsalsa208sha256-bytes-min 16
 p/scryptsalsa208sha256-bytes-max 0x1fffffffe0
 p/scryptsalsa208sha256-passwd-min 0
 p/scryptsalsa208sha256-saltbytes 32
 p/scryptsalsa208sha256-strbytes 102
 p/scryptsalsa208sha256-strprefix "$7$"
 p/scryptsalsa208sha256-opslimit-min 32768
 p/scryptsalsa208sha256-opslimit-max 4294967295
 p/scryptsalsa208sha256-memlimit-min 16777216
 p/scryptsalsa208sha256-opslimit-interactive 524288
 p/scryptsalsa208sha256-memlimit-interactive  16777216
 p/scryptsalsa208sha256-opslimit-sensitive 33554432
 p/scryptsalsa208sha256-memlimit-sensitive  1073741824)

(deftest pwhash-alg-default-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810" (u/hexify (p/pwhash 32 "password" salt p/opslimit-min p/memlimit-interactive p/alg-default))))))

(deftest pwhash-alg-argon2i-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810" (u/hexify (p/pwhash 32 "password" salt p/opslimit-min p/memlimit-interactive p/alg-argon2i13))))))

(deftest pwhash-str-and-verify-test-equal
  []
  (let [hashpass (p/pwhash-str "password" p/opslimit-min p/memlimit-interactive)
        result (p/pwhash-str-verify hashpass "password")]
    (is (= result 0))))

(deftest pwhash-str-and-verify-test-unequal
  []
  (let [hashpass (p/pwhash-str "password1" p/opslimit-min p/memlimit-interactive)
        result (p/pwhash-str-verify hashpass "password")]
    (is(not (= result 0)))))


(deftest pwhash-argon2i-alg-argon2i13-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810" (u/hexify (p/argon2i 32 "password" salt p/argon2i-opslimit-min p/argon2i-memlimit-interactive p/argon2i-alg-argon2i13))))))


(deftest argon2i-str-and-verify-test-equal
  []
  (let [hashpass (p/argon2i-str "password" p/argon2i-opslimit-min p/argon2i-memlimit-interactive)
        result (p/argon2i-str-verify hashpass "password")]
    (is (= result 0))))

(deftest argon2i-str-and-verify-test-unequal
  []
  (let [hashpass (p/argon2i-str "password1" p/argon2i-opslimit-min p/argon2i-memlimit-interactive)
        result (p/argon2i-str-verify hashpass "password")]
    (is(not (= result 0)))))


(deftest pwhash-argon2id-alg-argon2id13-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "75a10fdb4db0836498f824f1f0cc9ab9d3bb194d41b8dd66bd1ca6f0cf686810" (u/hexify (p/argon2id 32 "password" salt p/argon2id-opslimit-min p/argon2id-memlimit-interactive p/argon2id-alg-argon2id13))))))

(deftest argon2id-str-and-verify-test-equal
 []
  (let [hashpass (p/argon2id-str "password" p/argon2id-opslimit-min p/argon2id-memlimit-interactive)
       result (p/argon2id-str-verify hashpass "password")]
    (is (= result 0))))

(deftest pwhash-scryptsalsa208sha256-test
  []
  (let [salt (u/unhexify "7cb3b8ceb58e7847fc4485e63dbfdb9b7cb3b8ceb58e7847fc4485e63dbfdb9b")]
    (is (= "8f9a89dc959a951bf15b6cc29461f251973c6ea9df6880875423f2e15d0d3595" (u/hexify (p/scryptsalsa208sha256 32 "password" salt p/scryptsalsa208sha256-opslimit-min p/scryptsalsa208sha256-memlimit-interactive))))))

(deftest scryptsalsa208sha256-str-and-verify-test-equal
 []
  (let [hashpass (p/scryptsalsa208sha256-str "password" p/scryptsalsa208sha256-opslimit-min p/scryptsalsa208sha256-memlimit-interactive)
       result (p/scryptsalsa208sha256-str-verify hashpass "password")]
    (is (= result 0))))

(deftest scryptsalsa208sha256-str-and-verify-test-unequal
 []
  (let [hashpass (p/scryptsalsa208sha256-str "password" p/scryptsalsa208sha256-opslimit-min p/scryptsalsa208sha256-memlimit-interactive)
       result (p/scryptsalsa208sha256-str-verify hashpass "password1")]
    (is (not (= result 0)))))
