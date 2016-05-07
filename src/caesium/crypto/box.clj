(ns caesium.crypto.box
  "Bindings to the public key authenticated encryption scheme."
  (:require [caesium.binding :refer [defconsts sodium]]
            [caesium.crypto.scalarmult :as s])
  (:import (org.abstractj.kalium.keys KeyPair
                                      PublicKey
                                      PrivateKey)
           org.abstractj.kalium.crypto.Box))

(defconsts [seedbytes
            publickeybytes
            secretkeybytes
            noncebytes
            macbytes
            primitive])

(defn keypair-to-buf!
  "Generate a key pair into provided pk (public key) and sk (secret
  key) bufs. If also passed a seed, uses it to seed the key pair.

  This API matches libsodium's `crypto_box_keypair` and
  `crpyto_box_seed_keypair`."
  ([pk sk]
   (.crypto_box_keypair sodium pk sk))
  ([pk sk seed]
   (.crypto_box_seed_keypair sodium pk sk seed)))

(defn keypair!
  "Create a `crypto_box` keypair.

  This fn will take either:

  - nothing, generating the key pair from scratch securely
  - a seed, generating the key pair from the seed

  Previously, this API matched Kalium, where the seed would be used as the
  secret key directly. Now, it matches libsodium, where the seed is hashed
  before being used as a secret. The old behavior can be useful in some cases,
  e.g. if you are storage-constrained and only want to store secret keys, and
  you care that it is _really_ the secret key and not some value derived from
  it (you probably don't). See [[sk->keypair]] for details.

  Returns a map containing the public and private key bytes (mutable
  arrays)."
  ([]
   (let [pk (byte-array publickeybytes)
         sk (byte-array secretkeybytes)]
     (keypair-to-buf! pk sk)
     {:public pk :secret sk}))
  ([seed]
   (let [pk (byte-array publickeybytes)
         sk (byte-array secretkeybytes)]
     (keypair-to-buf! pk sk seed)
     {:public pk :secret sk})))

(def ^:deprecated generate-keypair
  "Deprecated alias for [[keypair!]].

  Please note that there was a breaking backwards-incompatible change between
  0.4.0 and 0.5.0+ if you specify a seed; see [[keypair!]] docs for details."
  keypair!)

(defn sk->keypair
  "Generates a key pair from a secret key.

  This is different from generating a key pair from a seed. The former
  uses the libsodium API which will first hash the secret to an array
  of appropriate length; this will use the secret key verbatim. To be
  precise: it will use the secret key as a scalar to perform the
  Curve25519 scalar mult."
  [sk]
  (let [pk (byte-array publickeybytes)]
    (s/scalarmult-to-buf! sk pk)
    {:public pk :secret sk}))

(defn encrypt
  "Encrypt with `crypto_box_easy`."
  [^bytes public-key
   ^bytes secret-key
   nonce
   plaintext]
  (let [pbk (PublicKey. public-key)
        pvk (PrivateKey. secret-key)]
    (.encrypt (Box. pbk pvk) nonce plaintext)))

(defn decrypt
  "Decrypt with `crypto_box_open_easy`."
  [^bytes public-key
   ^bytes secret-key
   nonce
   ciphertext]
  (let [pbk (PublicKey. public-key)
        pvk (PrivateKey. secret-key)]
    (.decrypt (Box. pbk pvk) nonce ciphertext)))
