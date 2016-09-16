(ns caesium.magicnonce.secretbox-test
  (:require [caesium.magicnonce.secretbox :as ms]
            [caesium.crypto.secretbox :as s]
            [caesium.crypto.secretbox-test :as st]
            [clojure.test :refer [deftest is]]
            [caesium.randombytes :as r]
            [caesium.util :as u]
            [caesium.crypto.generichash :as g]
            [caesium.byte-bufs :as bb]))

(deftest xor-test
  (let [one (byte-array [1 0 1])
        two (byte-array [0 1 0])
        out (byte-array [0 0 0])]
    (is (identical? (#'ms/xor! out one two) out))
    (is (bb/bytes= (byte-array [1 1 1]) out)))
  (let [one (byte-array [1 0 1])
        two (byte-array [0 1 0])]
    (is (identical? (#'ms/xor-inplace! one two) one))
    (is (bb/bytes= (byte-array [1 1 1]) one))))

(deftest random-nonce!-test
  (let [a (#'ms/random-nonce!)
        b (#'ms/random-nonce!)]
    (is (not (bb/bytes= a b)))
    (is (= s/noncebytes (bb/buflen a) (bb/buflen b)))))

(defn is-valid-magicnonce-ctext?
  "Does the given ctext decrypt properly?"
  [ctext]
  (let [ptextlen (bb/buflen st/ptext)]
    (is (= (+ s/noncebytes s/macbytes ptextlen)
           (bb/buflen ctext)))

    (let [out (bb/alloc ptextlen)]
      (ms/decrypt-to-buf!
       out
       (bb/->indirect-byte-buf st/secret-key)
       (bb/->indirect-byte-buf ctext))
      (is (bb/bytes= st/ptext out)))

    (let [out (bb/alloc ptextlen)
          forgery (bb/->indirect-byte-buf (r/randombytes (bb/buflen out)))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/decrypt-to-buf!
            out
            (bb/->indirect-byte-buf st/secret-key)
            forgery))))

    (is (bb/bytes= st/ptext (ms/decrypt st/secret-key ctext)))

    (let [forgery (r/randombytes (bb/buflen ctext))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/decrypt st/secret-key forgery))))

    (let [out (bb/alloc ptextlen)]
      (ms/open-to-buf!
       out
       (bb/->indirect-byte-buf ctext)
       (bb/->indirect-byte-buf st/secret-key))
      (is (bb/bytes= st/ptext out)))

    (let [out (bb/alloc ptextlen)
          forgery (bb/->indirect-byte-buf (r/randombytes (bb/buflen out)))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/open-to-buf!
            out
            forgery
            (bb/->indirect-byte-buf st/secret-key)))))

    (is (bb/bytes= st/ptext (ms/open ctext st/secret-key)))

    (let [forgery (r/randombytes (bb/buflen ctext))]
      (is (thrown-with-msg?
           RuntimeException #"Ciphertext verification failed"
           (ms/open forgery st/secret-key))))))

(defn repeated-keystream?
  "Does given scheme repeat the keystream when applied to given
  plaintexts?

  This compares the XORd ciphertexts to the XORd plaintexts. This will
  only be the same when the keystream repeats, and should not happen
  in an NMR scheme, or in a randomized scheme."
  ([scheme]
   (let [ptexts [(.getBytes "four score and ")
                 (.getBytes "seven years ago")]]
     (repeated-keystream? ptexts scheme)))
  ([ptexts scheme]
   (let [shortest (apply min (map alength ptexts))
         just-ctext (fn [^bytes ptext]
                      (->> (scheme ptext)
                           (drop (+ s/noncebytes s/macbytes))
                           (take shortest)
                           byte-array))
         ctexts (map just-ctext ptexts)
         xord-ptexts (byte-array shortest)
         xord-ctexts (byte-array shortest)]
     (apply #'ms/xor! xord-ptexts ptexts)
     (apply #'ms/xor! xord-ctexts ctexts)
     (bb/bytes= xord-ptexts xord-ctexts))))

(deftest secretbox-pfx-test
  (let [nonce (byte-array (range s/noncebytes))
        ctext (ms/secretbox-pfx st/ptext nonce st/secret-key)]
    (is (= (range s/noncebytes) (take s/noncebytes ctext)))
    (is-valid-magicnonce-ctext? ctext)
    (is (repeated-keystream? #(ms/secretbox-pfx % nonce st/secret-key)))))

(def constant-nonce (constantly (byte-array (range s/noncebytes))))

(deftest secretbox-rnd-test
  (let [ctext (ms/secretbox-rnd st/ptext st/secret-key)]
    (is-valid-magicnonce-ctext? ctext))

  (let [c1 (ms/secretbox-rnd st/ptext st/secret-key)
        c2 (ms/secretbox-rnd st/ptext st/secret-key)]
    (is (not (bb/bytes= c1 c2)))
    (is (not= (take s/noncebytes c1) (take s/noncebytes c2))))

  (with-redefs [ms/random-nonce! constant-nonce]
    (let [c1 (ms/secretbox-rnd st/ptext st/secret-key)
          c2 (ms/secretbox-rnd st/ptext st/secret-key)]
      (is (bb/bytes= c1 c2))
      (is (= (range s/noncebytes) (take s/noncebytes c1) (take s/noncebytes c2))))))

(deftest synthetic-nonce-test
  (is (= (bb/buflen @#'ms/synthetic-personal)
         g/blake2b-personalbytes))
  (let [k1 (byte-array (reverse (range 32)))
        k2 (byte-array (reverse (range 32 64)))
        sn #'ms/synthetic-nonce
        m1 (byte-array (range 10))
        m2 (byte-array (range 10 20))]
    (is (= s/noncebytes
           (bb/buflen (sn m1 k1))
           (bb/buflen (sn m2 k1))
           (bb/buflen (sn m1 k2))
           (bb/buflen (sn m2 k2))))
    (is (bb/bytes= (sn m1 k1) (sn m1 k1)))
    (is (not (bb/bytes= (sn m1 k1) (sn m2 k1))))
    (is (not (bb/bytes= (sn m1 k1) (sn m1 k2))))))

(deftest secretbox-det-test
  (let [ctext (ms/secretbox-det st/ptext st/secret-key)]
    (is-valid-magicnonce-ctext? ctext))

  (let [scheme (fn [ptext] (ms/secretbox-det ptext st/secret-key))]
    (is (not (repeated-keystream? scheme))))

  (let [c1 (ms/secretbox-det st/ptext st/secret-key)
        c2 (ms/secretbox-det st/ptext st/secret-key)]
    (is (bb/bytes= c1 c2))))

(deftest secretbox-nmr-with-implicit-rnd-nonce-test
  (let [ctext (ms/secretbox-nmr st/ptext st/secret-key)]
    (is-valid-magicnonce-ctext? ctext))

  (let [scheme (fn [ptext] (ms/secretbox-nmr ptext st/secret-key))]
    (is (not (repeated-keystream? scheme))))

  (with-redefs [ms/random-nonce! constant-nonce]
    (let [c1 (ms/secretbox-nmr st/ptext st/secret-key)
          c2 (ms/secretbox-nmr st/ptext st/secret-key)
          alt-ptext (.getBytes "yellow submarine")
          c3 (ms/secretbox-nmr alt-ptext st/secret-key)]
      (is (bb/bytes= c1 c2))
      (let [n1 (take s/noncebytes c1)
            n2 (take s/noncebytes c2)
            n3 (take s/noncebytes c3)]
        (is (= n1 n2))
        (is (not= n3 n1))))

    (let [scheme (fn [ptext] (ms/secretbox-nmr ptext st/secret-key))]
      (is (not (repeated-keystream? scheme))))))

(deftest secretbox-nmr-with-explicit-nonce-test
  (let [ctext (ms/secretbox-nmr st/ptext (byte-array 24) st/secret-key)]
    (is-valid-magicnonce-ctext? ctext))

  (let [scheme (fn [ptext]
                 (ms/secretbox-nmr ptext (byte-array 24) st/secret-key))]
    (is (not (repeated-keystream? scheme)))))
