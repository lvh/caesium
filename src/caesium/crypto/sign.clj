(ns caesium.crypto.sign
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :refer [defconsts sodium]]
            [caesium.byte-bufs :refer [buflen]]))

(defconsts [bytes seedbytes publickeybytes secretkeybytes primitive])

(defn keypair!
  "Generate a public-key and secret-key for signing with
  `crypto_sign_ed25519_seed_keypair`. If a seed is not provided, one
  is taken from `randombytes`.

  A map of the secret seed and public-key is returned."
  ([]
   (let [pk (byte-array publickeybytes)
         sk (byte-array secretkeybytes)]
     (.crypto_sign_keypair sodium pk sk)
     {:public pk
      :secret sk}))
  ([seed]
   (let [pk (byte-array publickeybytes)
         sk (byte-array secretkeybytes)]
     (.crypto_sign_seed_keypair sodium pk sk seed)
     {:public pk
      :secret sk})))

(def ^:deprecated generate-keypair
  "Deprecated alias for [[keypair!]]."
  keypair!)

(defn signed-to-buf!
  "Puts a signed version of the given message using given secret key into the
  given out buffer."
  [out sk m]
  (.crypto_sign sodium out nil m (buflen m) sk)
  out)

(defn signed
  "Produces a signed version of the given message m using given secret key."
  [sk m]
  (let [sm (byte-array (+ bytes (buflen m)))]
    (signed-to-buf! sm sk m)))

(defn sign-to-buf!
  "Puts a signature of the given message using given secret key into the given
  out buffer."
  [out sk m]
  (.crypto_sign_detached sodium out nil m (buflen m) sk)
  out)

(defn sign
  "Produces a detached signature for a message m using given secret key."
  [sk m]
  (let [sig (byte-array bytes)]
    (sign-to-buf! sig sk m)))

(defn verify
  "Verify a signed message or a message and a detached signature.

  When given a valid signed message, returns the unsigned
  message. When given a valid signature, returns nil. When given an
  invalid signed message or signature, raises RuntimeException."
  ([pk sm]
   (let [smlen (buflen sm)
         m (byte-array (- smlen bytes))
         res (.crypto_sign_open sodium m nil sm smlen pk)]
     (if (zero? res)
       m
       (throw (RuntimeException. "Signature validation failed")))))
  ([pk msg sig]
   (let [mlen (buflen msg)
         res (.crypto_sign_verify_detached sodium sig msg mlen pk)]
     (when-not (zero? res)
       (throw (RuntimeException. "Signature validation failed"))))))
