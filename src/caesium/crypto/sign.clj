(ns caesium.crypto.sign
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]))

(b/defconsts [bytes seedbytes publickeybytes secretkeybytes primitive])

(defn keypair!
  "Generate a public-key and secret-key for signing with
  `crypto_sign_ed25519_seed_keypair`. If a seed is not provided, one
  is taken from `randombytes`.

  A map of the secret seed and public-key is returned."
  ([]
   (let [pk (bb/alloc publickeybytes)
         sk (bb/alloc secretkeybytes)]
     (b/magic-sparkles sign-keypair pk sk)
     {:public pk :secret sk}))
  ([seed]
   (let [pk (bb/alloc publickeybytes)
         sk (bb/alloc secretkeybytes)
         seed (bb/->indirect-byte-buf seed)]
     (b/magic-sparkles sign-seed-keypair pk sk seed)
     {:public pk :secret sk})))

(def ^:deprecated generate-signing-keys
  "Deprecated alias for [[keypair!]]."
  keypair!)

(defn signed-to-buf!
  "Puts a signed version of the given message using given secret key into the
  given out buffer."
  [sm m sk]
  (b/magic-sparkles sign sm m sk)
  sm)

(defn signed
  "Produces a signed version of the given message m using given secret key."
  [m sk]
  (let [sm (bb/alloc (+ bytes (bb/buflen m)))]
    (signed-to-buf!
     sm
     (bb/->indirect-byte-buf m)
     (bb/->indirect-byte-buf sk))
    (bb/->bytes sm)))

(defn sign-to-buf!
  "Puts a signature of the given message using given secret key into the given
  out buffer."
  [sig m sk]
  (b/magic-sparkles sign-detached sig m sk)
  sig)

(defn sign
  "Produces a detached signature for a message m using given secret key."
  [m sk]
  (let [sig (bb/alloc bytes)]
    (sign-to-buf!
     sig
     (bb/->indirect-byte-buf m)
     (bb/->indirect-byte-buf sk))
    (bb/->bytes sig)))

(defn verify
  "Verify a signed message or a message and a detached signature.

  When given a valid signed message, returns the unsigned
  message. When given a valid signature, returns nil. When given an
  invalid signed message or signature, raises RuntimeException."
  ([sm pk]
   (let [m (bb/alloc (- (bb/buflen sm) bytes))
         sm (bb/->indirect-byte-buf sm)
         pk (bb/->indirect-byte-buf pk)
         res (b/magic-sparkles sign-open m sm pk)]
     (if (zero? res)
       (bb/->bytes m)
       (throw (RuntimeException. "Signature validation failed")))))
  ([sig m pk]
   (let [sig (bb/->indirect-byte-buf sig)
         m (bb/->indirect-byte-buf m)
         pk (bb/->indirect-byte-buf pk)
         res (b/magic-sparkles sign-verify-detached sig m pk)]
     (when-not (zero? res)
       (throw (RuntimeException. "Signature validation failed"))))))
