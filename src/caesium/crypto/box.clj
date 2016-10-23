(ns caesium.crypto.box
  "Bindings to the public key authenticated encryption scheme."
  (:require [caesium.binding :as b]
            [caesium.crypto.scalarmult :as s]
            [caesium.byte-bufs :as bb])
  (:import [java.nio ByteBuffer]))

(b/defconsts [seedbytes
              publickeybytes
              secretkeybytes
              noncebytes
              macbytes
              sealbytes
              primitive])

(defn keypair-to-buf!
  "Generate a key pair into provided pk (public key) and sk (secret
  key) bufs. If also passed a seed, uses it to seed the key pair.

  This API matches libsodium's `crypto_box_keypair` and
  `crpyto_box_seed_keypair`."
  ([pk sk]
   (b/✨ keypair pk sk))
  ([pk sk seed]
   (b/✨ seed-keypair pk sk seed)))

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
   (let [pk (bb/alloc publickeybytes)
         sk (bb/alloc secretkeybytes)]
     (keypair-to-buf! pk sk)
     {:public pk :secret sk}))
  ([seed]
   (let [pk (bb/alloc publickeybytes)
         sk (bb/alloc secretkeybytes)]
     (keypair-to-buf! pk sk (bb/->indirect-byte-buf seed))
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
  (let [pk (bb/alloc publickeybytes)]
    (s/scalarmult-to-buf! pk sk)
    {:public pk :secret sk}))

(defn box-easy-to-buf!
  "Encrypts ptext into out with `crypto_box_easy` using given nonce,
  public key and secret key.

  All arguments must be `java.nio.ByteBuffer`.

  This function is only useful if you're managing your own output
  buffer, which includes in-place encryption. You probably
  want [[box-easy]]."
  [c m n pk sk]
  (b/✨ easy c m plen n pk sk)
  c)

(defn box-open-easy-to-buf!
  "Decrypts ptext into out with `crypto_box_open_easy` using given
  nonce, public key and secret key.

  All arguments must be `java.nio.ByteBuffer`.

  This function is only useful if you're managing your own output
  buffer, which includes in-place decryption. You probably
  want [[box-open-easy]]."
  [m c n pk sk]
  (let [res (b/✨ open-easy m c n pk sk)]
    (if (zero? res)
      m
      (throw (RuntimeException. "Ciphertext verification failed")))))

(defn box-seal-to-buf!
  "Encrypts ptext into out with `crypto_box_seal` using given public key.

  All arguments must be `java.nio.ByteBuffer`.

  This function is only useful if you're managing your own output
  buffer, which includes in-place encryption. You probably
  want [[box-seal]]."
  [c m pk]
  (b/✨ box-seal c m plen pk)
  c)

(defn box-seal-open-to-buf!
  "Decrypts ptext into out with `crypto_box_seal_open` using given
  public key and secret key.

  All arguments must be `java.nio.ByteBuffer`.

  This function is only useful if you're managing your own output
  buffer, which includes in-place decryption. You probably
  want [[box-seal-open]]."
  [m c pk sk]
  (let [res (b/✨ seal-open m c plen pk sk)]
    (if (zero? res)
      m
      (throw (RuntimeException. "Ciphertext verification failed")))))

(defn mlen->clen
  "Given a plaintext length, return the ciphertext length.

  This should be an implementation detail unless you want to manage
  your own output buffer together with [[box-easy-to-buf!]]."
  [mlen]
  (+ mlen macbytes))

(defn clen->mlen
  "Given a ciphertext length, return the plaintext length.

  This should be an implementation detail unless you want to manage
  your own output buffer together with [[box-open-easy-to-buf!]]."
  [clen]
  (- clen macbytes))

(defn box-easy
  "Encrypts ptext with `crypto_box_easy` using given nonce, public key
  and secret key.

  This creates the output ciphertext byte array for you, which is
  probably what you want. If you would like to manage the array
  yourself, or do in-place encryption, see [[box-easy-to-buf!]]."
  [ptext nonce pk sk]
  (let [out (bb/alloc (mlen->clen (bb/buflen ptext)))]
    (box-easy-to-buf!
     out
     (bb/->indirect-byte-buf ptext)
     (bb/->indirect-byte-buf nonce)
     (bb/->indirect-byte-buf pk)
     (bb/->indirect-byte-buf sk))
    (bb/->bytes out)))

(defn box-open-easy
  "Decrypts ptext with `crypto_box_open_easy` using given nonce, public
  key and secret key.

  This creates the output plaintext byte array for you, which is probably what
  you want. If you would like to manage the array yourself, or do in-place
  decryption, see [[box-open-easy-to-buf!]]."
  [ctext nonce pk sk]
  (let [out (bb/alloc (clen->mlen (bb/buflen ctext)))]
    (box-open-easy-to-buf!
     out
     (bb/->indirect-byte-buf ctext)
     (bb/->indirect-byte-buf nonce)
     (bb/->indirect-byte-buf pk)
     (bb/->indirect-byte-buf sk))
    (bb/->bytes out)))

(defn box-seal
  "Encrypts ptext with `crypto_box_seal` using given public key.

  This creates the output ciphertext byte array for you, which is
  probably what you want. If you would like to manage the array
  yourself, or do in-place encryption, see [[box-seal-to-buf!]]."
  [ptext pk]
  (let [out (bb/alloc (+ (bb/buflen ptext) sealbytes))]
    (box-seal-to-buf!
     out
     (bb/->indirect-byte-buf ptext)
     (bb/->indirect-byte-buf pk))
    (bb/->bytes out)))

(defn box-seal-open
  "Decrypts ptext with `crypto_box_seal_open` using given public key, and
  secret key.

  This creates the output plaintext byte array for you, which is probably what
  you want. If you would like to manage the array yourself, or do in-place
  decryption, see [[box-seal-open-to-buf!]]."
  [ctext pk sk]
  (let [out (bb/alloc (- (bb/buflen ctext) sealbytes))]
    (box-seal-open-to-buf!
     out
     (bb/->indirect-byte-buf ctext)
     (bb/->indirect-byte-buf pk)
     (bb/->indirect-byte-buf sk))
    (bb/->bytes out)))

(defn encrypt
  "Encrypt with `crypto_box_easy`.

  To encrypt, use the recipient's public key and the sender's secret
  key.

  This is an alias for [[box-easy]] with a different argument
  order. [[box-easy]] follows the same argument order as the libsodium
  function."
  [pk sk nonce ptext]
  (box-easy ptext nonce pk sk))

(defn decrypt
  "Decrypt with `crypto_box_open_easy`.

  To decrypt, use the sender's public key and the recipient's secret
  key.

  This is an alias for [[box-open-easy]] with a different argument
  order. [[box-open-easy]] follows the same argument order as the
  libsodium function."
  [pk sk nonce ctext]
  (box-open-easy ctext nonce pk sk))

(defn anonymous-encrypt
  "Encrypt with `crypto_box_seal`.

  To encrypt, use the recipient's public key.

  This is an alias for [[box-seal]] with a different argument
  order. [[box-seal]] follows the same argument order as the libsodium
  function."
  [pk ptext]
  (box-seal ptext pk))

(defn anonymous-decrypt
  "Decrypt with `crypto_box_seal_open`.

  To decrypt, use the recipient's public key and recipient' secret
  key.

  This is an alias for [[box-seal-open]] with a different argument
  order. [[box-seal-open]] follows the same argument order as the
  libsodium function."
  [pk sk ctext]
  (box-seal-open ctext pk sk))
