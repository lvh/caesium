(ns caesium.crypto.scalarmult-test
  (:require [caesium.crypto.scalarmult :as s]
            [caesium.test-utils :refer [const-test]]
            [caesium.util :as u]
            [caesium.byte-bufs :as bb]
            [clojure.test :refer [are deftest is testing]]))

(const-test
 s/bytes 32
 s/scalarbytes 32
 s/primitive "curve25519")

(def basepoint
  (byte-array (into [9] (repeat (dec s/bytes) 0))))

(def ^bytes ^:private int->scalar
  "**DANGER** This fn is typically only used for demos, not secure
  cryptosystems; see rest of docstring for details. Turns an integral
  type (int, bigint, biginteger) into a byte array suitable for use as
  a scalar for scalarmult.

  The resulting byte array will be `scalarbytes` wide.

  Note that int is generally only 32 bits wide (see `Integer/SIZE`),
  whereas scalars here are 32 bytes wide (see `scalarbytes`). An
  attacker can simply exhaust all 32-bit options, so points generated
  this way should not be considered secure."
  (partial u/n->bytes s/scalarbytes))

(deftest int->scalar-test
  (are [n expected] (bb/bytes= expected (int->scalar n))
    0 (byte-array 32)
    0M (byte-array 32)
    1000000000000 (byte-array (into (vec (repeat 27 0))
                                    [-24 -44 -91 16 0]))))

(def scalar-1
  "The number 1, as a curve25519 scalar."
  (int->scalar 1))

(deftest scalarmult-tests
  (testing "-to-buf! and regular API work identically"
    (let [q (bb/alloc s/bytes)
          r (s/scalarmult scalar-1)]
      (s/scalarmult-to-buf! q (bb/->indirect-byte-buf scalar-1))
      (is (bb/bytes= r q))))
  (testing "base point mult uses the base point"
    (is (bb/bytes=
         (s/scalarmult scalar-1)
         (s/scalarmult scalar-1 basepoint)))))
