(ns caesium.magicnonce.secretbox-test
  (:require [caesium.magicnonce.secretbox :as ms]
            [caesium.crypto.secretbox :as s]
            [caesium.crypto.secretbox-test :as st]
            [clojure.test :refer [deftest is]]
            [caesium.randombytes :as r]
            [caesium.util :as u]))

(deftest xor-test
  (let [one (byte-array [1 0 1])
        two (byte-array [0 1 0])
        out (byte-array [0 0 0])]
    (is (identical? (#'ms/xor! out one two) out))
    (is (u/array-eq (byte-array [1 1 1]) out)))
  (let [one (byte-array [1 0 1])
        two (byte-array [0 1 0])]
    (is (identical? (#'ms/xor-inplace! one two) one))
    (is (u/array-eq (byte-array [1 1 1]) one))))

(deftest random-nonce!-test
  (let [a (#'ms/random-nonce!)
        b (#'ms/random-nonce!)]
    (is (not (u/array-eq a b)))
    (is (= s/noncebytes (alength ^bytes a) (alength ^bytes b)))))

(deftest secretbox-pfx-test
  (let [nonce (byte-array (range s/noncebytes))
        ctext (ms/secretbox-pfx st/ptext nonce st/secret-key)
        ptextlen (alength ^bytes st/ptext)]
    (is (= (+ s/noncebytes ptextlen s/macbytes)
           (alength ^bytes ctext)))
    (is (= (range s/noncebytes)
           (take s/noncebytes ctext)))

    (let [out (byte-array ptextlen)]
      (ms/decrypt-to-buf! out st/secret-key ctext)
      (is (u/array-eq st/ptext out)))

    (let [out (byte-array ptextlen)
          forgery (r/randombytes (alength ^bytes out))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/decrypt-to-buf! out st/secret-key forgery))))

    (is (u/array-eq st/ptext (ms/decrypt st/secret-key ctext)))

    (let [forgery (r/randombytes (alength ^bytes ctext))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/decrypt st/secret-key forgery))))

    (let [out (byte-array ptextlen)]
      (ms/open-to-buf! out ctext st/secret-key)
      (is (u/array-eq st/ptext out)))

    (let [out (byte-array ptextlen)
          forgery (r/randombytes (alength ^bytes out))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/open-to-buf! out forgery st/secret-key))))

    (is (u/array-eq st/ptext (ms/open ctext st/secret-key)))

    (let [forgery (r/randombytes (alength ^bytes ctext))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/open forgery st/secret-key))))))

(deftest secretbox-rnd-test
  (let [ctext (ms/secretbox-rnd st/ptext st/secret-key)
        ptextlen (alength ^bytes st/ptext)]
    (is (= (+ s/noncebytes ptextlen s/macbytes)
           (alength ^bytes ctext)))

    (let [out (byte-array ptextlen)]
      (ms/decrypt-to-buf! out st/secret-key ctext)
      (is (u/array-eq st/ptext out)))

    (let [out (byte-array ptextlen)
          forgery (r/randombytes (alength ^bytes out))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/decrypt-to-buf! out st/secret-key forgery))))

    (is (u/array-eq st/ptext (ms/decrypt st/secret-key ctext)))

    (let [forgery (r/randombytes (alength ^bytes ctext))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/decrypt st/secret-key forgery))))

    (let [out (byte-array ptextlen)]
      (ms/open-to-buf! out ctext st/secret-key)
      (is (u/array-eq st/ptext out)))

    (let [out (byte-array ptextlen)
          forgery (r/randombytes (alength ^bytes out))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/open-to-buf! out forgery st/secret-key))))

    (is (u/array-eq st/ptext (ms/open ctext st/secret-key)))

    (let [forgery (r/randombytes (alength ^bytes ctext))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/open forgery st/secret-key)))))

  (let [c1 (ms/secretbox-rnd st/ptext st/secret-key)
        c2 (ms/secretbox-rnd st/ptext st/secret-key)]
    (is (not (u/array-eq c1 c2)))
    (is (not= (take s/noncebytes c1) (take s/noncebytes c2))))

  (with-redefs [ms/random-nonce! (constantly (byte-array (range s/noncebytes)))]
    (let [c1 (ms/secretbox-rnd st/ptext st/secret-key)
          c2 (ms/secretbox-rnd st/ptext st/secret-key)]
      (is (u/array-eq c1 c2))
      (is (= (range s/noncebytes) (take s/noncebytes c1) (take s/noncebytes c2))))))
