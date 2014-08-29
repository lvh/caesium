(ns caesium.crypto.secretbox-test
  (:require [caesium.crypto.secretbox :refer :all]
            [caesium.crypto.util :refer [array-eq unhexify]]
            [clojure.test :refer :all]))

(def message (byte-array [80 117 114 101 32 105 110 116 101 110 116 105 111 110 32 106 117 120 116 97 112 111 115 101 100]))
(def secret-key (byte-array (range 32)))

(deftest secretbox-kat-test
  (testing "Implementation handles several KATs; decrypt & encrypt roundtrip"
    (are [secret-key nonce plaintext ciphertext] (and (array-eq (encrypt secret-key nonce plaintext)
                                                                ciphertext)
                                                      (array-eq (decrypt secret-key nonce ciphertext)
                                                                plaintext))
         secret-key (int->nonce 0) message (unhexify "cb97a2f8b60ea0cafd933dd497c0eddc1a7b8224b8c3d147393a06664a289eb8914c009137895b290f")
         secret-key (int->nonce 1) message (unhexify "74f47d0db1fc9d22265d85218cd546e1924ef845d27696ba971614282f0a6647a23b481a91dd20399a")))
  (testing "Decrypting bogus ciphertexts causes exceptions"
    (are [secret-key nonce ciphertext] (thrown-with-msg? RuntimeException #"Decryption failed. Ciphertext failed verification"
                                                  (decrypt secret-key nonce ciphertext))
         secret-key (int->nonce 1) (unhexify "74f47d0db1fc9d22265d85218cd546e1924ef845d27696ba971614282f0a6647a23b481a91dd203990"))))

(deftest int->nonce-test
  (testing "Turning numbers into nonces works"
    (are [n nonce] (array-eq (int->nonce n)
                             nonce)
         0 (byte-array 24)
         0M (byte-array 24)
         1000000000000 (byte-array [0, -24, -44, -91, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))))
