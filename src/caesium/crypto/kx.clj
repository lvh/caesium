(ns caesium.crypto.kx
  (:require [caesium.binding :as b]
            [caesium.crypto.scalarmult :as s]
            [caesium.byte-bufs :as bb])
  (:import [java.nio ByteBuffer]))

(declare seedbytes publickeybytes secretkeybytes sessionkeybytes primitive)
(b/defconsts [seedbytes publickeybytes secretkeybytes sessionkeybytes primitive])

(defn keypair-to-buf!
  "Generate a key pair into provided pk (public key) and sk (secret
  key) bufs. If also passed a seed, uses it to seed the key pair.

  This API matches libsodium's `crypto_kx_keypair` and
  `crypto_kx_seed_keypair`."
  ([pk sk]
   (b/call! keypair pk sk))
  ([pk sk seed]
   (b/call! seed-keypair pk sk seed)))

(defn keypair!
  "Create a `crypto_kx_box` keypair.

  This fn will take either:

  - nothing, generating the key pair from scratch securely
  - a seed, generating the key pair from the seed

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

(defn client-session-keys-to-buf!
  "Compute a pair of shared keys, `client-rx` and `client-tx`,
  using the client keypair and the server public key.
  Matches libsodium API for `crypto-kx-client-session-keys`.
  A map of the receive and transmit keys is returned.

  All arguments must be `java.nio.ByteBuffer`."
  [client-rx client-tx client-pk client-sk server-pk]
  (let [client-rx (bb/->indirect-byte-buf client-rx)
        client-tx (bb/->indirect-byte-buf client-tx)
        client-pk (bb/->indirect-byte-buf client-pk)
        client-sk (bb/->indirect-byte-buf client-sk)
        server-pk (bb/->indirect-byte-buf server-pk)
        result (.crypto_kx_client_session_keys b/sodium client-rx client-tx client-pk client-sk server-pk)]
    (if-not (zero? result)
      (throw (RuntimeException. "Unable to calculate client session keys"))
      {:client-rx client-rx
       :client-tx client-tx})))

(defn server-session-keys-to-buf!
  "Compute a pair of shared keys, `server-rx` and `server-tx`,
  using the server keypair and the client public key.
  Matches libsodium API for `crypto-kx-server-session-keys`.
  A map of the receive and transmit keys is returned.

  All arguments must be `java.nio.ByteBuffer`."
  [server-rx server-tx server-pk server-sk client-pk]
  (let [server-rx (bb/->indirect-byte-buf server-rx)
        server-tx (bb/->indirect-byte-buf server-tx)
        server-pk (bb/->indirect-byte-buf server-pk)
        server-sk (bb/->indirect-byte-buf server-sk)
        client-pk (bb/->indirect-byte-buf client-pk)
        result (.crypto_kx_server_session_keys b/sodium server-rx server-tx server-pk server-sk client-pk)]
    (if-not (zero? result)
      (throw (RuntimeException. "Unable to calculate server session keys"))
      {:server-rx server-rx
       :server-tx server-tx})))

(defn client-session-keys
  "Compute a pair of shared keys, `client-rx` and `client-tx`,
  using the client keypair and the server public key.
  A map of the receive and transmit keys is returned.

  All arguments must be `java.nio.ByteBuffer`."
  ([client-keypair server-pk]
   (client-session-keys (:public client-keypair) (:secret client-keypair) server-pk))
  ([client-pk client-sk server-pk]
   (let [client-rx (bb/alloc sessionkeybytes)
         client-tx (bb/alloc sessionkeybytes)]
     (client-session-keys-to-buf! client-rx client-tx client-pk client-sk server-pk))))

(defn server-session-keys
  "Compute a pair of shared keys, `server-rx` and `server-tx`,
  using the server keypair and the client public key.
  A map of the receive and transmit keys is returned.

  All arguments must be `java.nio.ByteBuffer`."
  ([server-keypair client-pk]
   (server-session-keys (:public server-keypair) (:secret server-keypair) client-pk))
  ([server-pk server-sk client-pk]
   (let [server-rx (bb/alloc sessionkeybytes)
         server-tx (bb/alloc sessionkeybytes)]
     (server-session-keys-to-buf! server-rx server-tx server-pk server-sk client-pk))))
