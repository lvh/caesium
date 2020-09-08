(ns caesium.crypto.core.ristretto255-test
  "The Ristretto255 core tests ported from:
  https://github.com/jedisct1/libsodium/blob/master/test/default/core_ristretto255.c"
  (:require [caesium.crypto.core.ristretto255 :as sut]
            [caesium.crypto.core.ristretto255.scalar :as suts]
            [caesium.crypto.scalarmult.ristretto255 :as sutsm]
            [caesium.test-utils :refer [const-test]]
            [caesium.vectors :as v]
            [clojure.test :refer [deftest is are testing]]
            [caesium.byte-bufs :as bb]
            [caesium.util :as u]
            [caesium.crypto.hash :as ch]
            [caesium.randombytes :as rb]))

(const-test
 sut/bytes 32
 sut/hashbytes 64
 sut/scalarbytes 32
 sut/nonreducedscalarbytes 64)

(def ristretto255-vector
  (comp v/hex-resource (partial str "vectors/ristretto255/")))

(def ristretto255-vectors
  (comp v/hex-resources (partial str "vectors/ristretto255/")))

(def ristretto255-text-vectors
  (comp v/string-resources (partial str "vectors/ristretto255/")))

(defn test-encodings
  [name pred]
  (doseq [x (ristretto255-vectors name)]
      (is (pred (sut/valid-point? x)))))

(deftest valid-point?-test
  (testing "rejects non-canonical field encodings"
    (test-encodings "bad-encodings-non-canonical" false?))
  (testing "rejects negative field elements"
    (test-encodings "bad-encodings-negative" false?))
  (testing "rejects non-square x^2"
    (test-encodings "bad-encodings-non-square-x-pow-2" false?))
  (testing "rejects negative xy value"
    (test-encodings "bad-encodings-negative-xy" false?))
  (testing "rejects s = -1, which causes y = 0"
    (test-encodings "bad-encodings-s-eq-minus-1" false?)))

(deftest to-hash-libsodium-test
  ;; This is a direct port of the tv2 test from the
  ;; libsodium test suite:
  ;; https://github.com/jedisct1/libsodium/blob/33b935921c91eb7832296a6387d3f8dfbfa7e385/test/default/core_ristretto255.c#L64
  (are [h res] (bb/bytes= (sut/hash->group (u/unhexify h)) (u/unhexify res))
    (str "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1"
         "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6")
    "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46"
    
    (str "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b27"
         "0102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38")
    "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b"
    
    (str "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c"
         "27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c")
    "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826"
    
    (str "ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2"
         "150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf")
    "f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a"
    
    (str "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec767"
         "5debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413")
    "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179"
    
    (str "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2"
         "979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c")
    "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628"
    
    (str "2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c7462"
         "2c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982")
    "80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065"))

(deftest to-hash-ristretto-group-test
  (doseq [[s res]
          (partition
           2
           (interleave (ristretto255-text-vectors "labels")
                       (ristretto255-vectors "encoded-hash-to-points")))]
    (is (bb/bytes= (sut/hash->group (ch/sha512 s)) res))))

(deftest tv3-libsodium-test
  ;; This is a direct port of the tv3 test from the
  ;; libsodium test suite:
  ;; https://github.com/jedisct1/libsodium/blob/33b935921c91eb7832296a6387d3f8dfbfa7e385/test/default/core_ristretto255.c#L111
  (let [l (u/unhexify "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")]
    (dotimes [_ 1000]
      (let [r (suts/random)
            s (sutsm/scalarmult r)]
        (is (sut/valid-point? s))
        (let [s (sut/random)]
          (is (sut/valid-point? s))
          (is (thrown? RuntimeException (sutsm/scalarmult l s))
              "s*l != inf (1)"))
        (let [ru (rb/randombytes sut/hashbytes)
              s (sut/hash->group ru)]
          (is (sut/valid-point? s))
          (is (thrown? RuntimeException (sutsm/scalarmult l s))
              "s*l != inf (2)")
          (let [s2 (sutsm/scalarmult r s)]
            (is (sut/valid-point? s2))
            (is (thrown? RuntimeException (sutsm/scalarmult l s2))
                "s*l != inf (3)")
            (let [r-inv (suts/invert r)
                  s_ (sutsm/scalarmult r-inv s2)]
              (is (sut/valid-point? s_))
              (is (bb/bytes= s s_)
                  "inversion failed")
              (let [s2 (sut/add s s_)
                    s2 (sut/sub s2 s_)]
                (is (sut/valid-point? s2))
                (is (bb/bytes= s s2)
                    "s2 + s - s_ != s")
                (let [s2 (sut/sub s2 s)]
                  (is (sut/valid-point? s2)
                      "s + s' - s - s' != 0")))))))))
  (let [s (sut/random)
        s_ (u/unhexify (apply str (repeat sut/bytes "fe")))]
    (is (thrown? RuntimeException (sut/add s_ s)))
    (is (thrown? RuntimeException (sut/add s s_)))
    (is (thrown? RuntimeException (sut/add s_ s_)))
    (sut/add s s)
    (is (thrown? RuntimeException (sut/sub s_ s)))
    (is (thrown? RuntimeException (sut/sub s s_)))
    (is (thrown? RuntimeException (sut/sub s_ s_)))
    (sut/sub s s)))

(deftest tv4-libsodium-test
  ;; This is a direct port of the tv4 test from the
  ;; libsodium test suite:
  ;; https://github.com/jedisct1/libsodium/blob/33b935921c91eb7832296a6387d3f8dfbfa7e385/test/default/core_ristretto255.c#L211
  (let [s1 (suts/random)
        r (rb/randombytes sut/nonreducedscalarbytes)
        s2 (suts/reduce r)
        s3 (suts/add s1 s2)
        s4 (suts/sub s1 s2)
        s2 (suts/add s3 s4)
        s2 (suts/sub s2 s1)
        s2 (suts/mul s3 s2)
        s4 (suts/invert s3)
        s2 (suts/mul s2 s4)
        s1 (suts/negate s1)
        s2 (suts/add s2 s1)
        s1 (suts/complement s2)]
    (is (bb/bytes= s1 (u/unhexify "0100000000000000000000000000000000000000000000000000000000000000")))))

