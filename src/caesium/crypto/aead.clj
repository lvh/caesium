(ns caesium.crypto.aead
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]
            [caesium.randombytes :as r]))

(b/defconsts [chacha20poly1305-ietf-keybytes
              chacha20poly1305-ietf-nsecbytes
              chacha20poly1305-ietf-npubbytes
              chacha20poly1305-ietf-abytes
              chacha20poly1305-keybytes
              chacha20poly1305-nsecbytes
              chacha20poly1305-npubbytes
              chacha20poly1305-abytes
              xchacha20poly1305-ietf-keybytes
              xchacha20poly1305-ietf-nsecbytes
              xchacha20poly1305-ietf-npubbytes
              xchacha20poly1305-ietf-abytes])

(defn ^:private chacha20poly1305-ietf-keygen-to-buf! [k]
  (b/call! chacha20poly1305-ietf-keybytes k))

(defn chacha20poly1305-ietf-keygen []
  "Generates a new random key."
  (let [k (bb/alloc chacha20poly1305-ietf-keybytes)]
    (chacha20poly1305-ietf-keygen-to-buf! k)
    k))

(defn new-chacha20poly1305-ietf-nonce
  "Generates a new random nonce."
  []
  (r/randombytes chacha20poly1305-ietf-npubbytes))

(defn ^:private chacha20poly1305-ietf-encrypt-to-buf!
  [c m ad nsec npub k]
  (b/call! chacha20poly1305-ietf-encrypt c m ad nsec npub k)
  c)

(defn chacha20poly1305-ietf-encrypt
  "Encrypts a message using a secret key and public nonce."
  [m ad npub k]
  (let [c (bb/alloc (+ (bb/buflen m) chacha20poly1305-ietf-abytes))]
    (chacha20poly1305-ietf-encrypt-to-buf!
     c
     (bb/->indirect-byte-buf m)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    (bb/->bytes c)))

(defn ^:private chacha20poly1305-ietf-decrypt-to-buf!
  [m nsec c ad npub k]
  (b/call! chacha20poly1305-ietf-decrypt m nsec c ad npub k)
  c)

(defn chacha20poly1305-ietf-decrypt
  [c ad npub k]
  (let [m (bb/alloc (- (bb/buflen c) chacha20poly1305-ietf-abytes))]
    (chacha20poly1305-ietf-decrypt-to-buf!
     m
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf c)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    (bb/->bytes m)))

(defn ^:private chacha20poly1305-ietf-encrypt-detached-to-buf!
  [c mac m ad nsec npub k]
  (b/call! chacha20poly1305-ietf-encrypt-detached c mac m ad nsec npub k))

(defn chacha20poly1305-ietf-encrypt-detached
  "Encrypts a message using a secret key and public nonce.
  It returns the cyphertext and auth tag in different hash keys"
  [m ad npub k]
  (let [c (bb/alloc (bb/buflen m))
        mac (bb/alloc chacha20poly1305-ietf-abytes)]
    (chacha20poly1305-ietf-encrypt-detached-to-buf!
     c
     mac
     (bb/->indirect-byte-buf m)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    {:c (bb/->bytes c) :mac (bb/->bytes mac)}))

(defn ^:private chacha20poly1305-ietf-decrypt-detached-to-buf!
  [m nsec c mac ad npub k]
  (b/call! chacha20poly1305-ietf-decrypt-detached m nsec c mac ad npub k)
  c)

(defn chacha20poly1305-ietf-decrypt-detached
  [c mac ad npub k]
  (let [m (bb/alloc (bb/buflen c))]
    (chacha20poly1305-ietf-decrypt-detached-to-buf!
     m
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf c)
     (bb/->indirect-byte-buf mac)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    (bb/->bytes m)))

(defn ^:private chacha20poly1305-keygen-to-buf! [k]
  (b/call! chacha20poly1305-keybytes k))

(defn chacha20poly1305-keygen []
  "Generates a new random key."
  (let [k (bb/alloc chacha20poly1305-keybytes)]
    (chacha20poly1305-ietf-keygen-to-buf! k)
    k))

(defn new-chacha20poly1305-nonce
  "Generates a new random nonce."
  []
  (r/randombytes chacha20poly1305-npubbytes))

(defn ^:private chacha20poly1305-encrypt-to-buf!
  [c m ad nsec npub k]
  (b/call! chacha20poly1305-encrypt c m ad nsec npub k)
  c)

(defn chacha20poly1305-encrypt
  "Encrypts a message using a secret key and public nonce."
  [m ad npub k]
  (let [c (bb/alloc (+ (bb/buflen m) chacha20poly1305-abytes))]
    (chacha20poly1305-encrypt-to-buf!
     c
     (bb/->indirect-byte-buf m)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    (bb/->bytes c)))

(defn ^:private chacha20poly1305-decrypt-to-buf!
  [m nsec c ad npub k]
  (b/call! chacha20poly1305-decrypt m nsec c ad npub k)
  c)

(defn chacha20poly1305-decrypt
  [c ad npub k]
  (let [m (bb/alloc (- (bb/buflen c) chacha20poly1305-abytes))]
    (chacha20poly1305-decrypt-to-buf!
     m
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf c)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    (bb/->bytes m)))

(defn ^:private chacha20poly1305-encrypt-detached-to-buf!
  [c mac m ad nsec npub k]
  (b/call! chacha20poly1305-encrypt-detached c mac m ad nsec npub k))

(defn chacha20poly1305-encrypt-detached
  "Encrypts a message using a secret key and public nonce.
  It returns the cyphertext and auth tag in different hash keys"
  [m ad npub k]
  (let [c (bb/alloc (bb/buflen m))
        mac (bb/alloc chacha20poly1305-abytes)]
    (chacha20poly1305-encrypt-detached-to-buf!
     c
     mac
     (bb/->indirect-byte-buf m)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    {:c (bb/->bytes c) :mac (bb/->bytes mac)}))

(defn ^:private chacha20poly1305-decrypt-detached-to-buf!
  [m nsec c mac ad npub k]
  (b/call! chacha20poly1305-decrypt-detached m nsec c mac ad npub k)
  c)

(defn chacha20poly1305-decrypt-detached
  [c mac ad npub k]
  (let [m (bb/alloc (bb/buflen c))]
    (chacha20poly1305-decrypt-detached-to-buf!
     m
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf c)
     (bb/->indirect-byte-buf mac)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    (bb/->bytes m)))

(defn ^:private xchacha20poly1305-ietf-keygen-to-buf! [k]
  (b/call! xchacha20poly1305-keybytes k))

(defn xchacha20poly1305-ietf-keygen []
  "Generates a new random key."
  (let [k (bb/alloc xchacha20poly1305-ietf-keybytes)]
    (chacha20poly1305-keygen-to-buf! k)
    k))

(defn new-xchacha20poly1305-ietf-nonce
  "Generates a new random nonce."
  []
  (r/randombytes xchacha20poly1305-ietf-npubbytes))

(defn ^:private xchacha20poly1305-encrypt-to-buf!
  [c m ad nsec npub k]
  (b/call! xchacha20poly1305-ietf-encrypt c m ad nsec npub k)
  c)

(defn xchacha20poly1305-ietf-encrypt
  "Encrypts a message using a secret key and public nonce."
  [m ad npub k]
  (let [c (bb/alloc (+ (bb/buflen m) xchacha20poly1305-ietf-abytes))]
    (xchacha20poly1305-encrypt-to-buf!
     c
     (bb/->indirect-byte-buf m)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    (bb/->bytes c)))

(defn ^:private xchacha20poly1305-ietf-decrypt-to-buf!
  [m nsec c ad npub k]
  (b/call! xchacha20poly1305-ietf-decrypt m nsec c ad npub k)
  c)

(defn xchacha20poly1305-ietf-decrypt
  [c ad npub k]
  (let [m (bb/alloc (- (bb/buflen c) xchacha20poly1305-ietf-abytes))]
    (xchacha20poly1305-ietf-decrypt-to-buf!
     m
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf c)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    (bb/->bytes m)))

(defn ^:private xchacha20poly1305-ietf-encrypt-detached-to-buf!
  [c mac m ad nsec npub k]
  (b/call! xchacha20poly1305-ietf-encrypt-detached c mac m ad nsec npub k))

(defn xchacha20poly1305-ietf-encrypt-detached
  "Encrypts a message using a secret key and public nonce.
  It returns the cyphertext and auth tag in different hash keys"
  [m ad npub k]
  (let [c (bb/alloc (bb/buflen m))
        mac (bb/alloc xchacha20poly1305-ietf-abytes)]
    (xchacha20poly1305-ietf-encrypt-detached-to-buf!
     c
     mac
     (bb/->indirect-byte-buf m)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    {:c (bb/->bytes c) :mac (bb/->bytes mac)}))

(defn ^:private xchacha20poly1305-ietf-decrypt-detached-to-buf!
  [m nsec c mac ad npub k]
  (b/call! xchacha20poly1305-ietf-decrypt-detached m nsec c mac ad npub k)
  c)

(defn xchacha20poly1305-ietf-decrypt-detached
  [c mac ad npub k]
  (let [m (bb/alloc (bb/buflen c))]
    (xchacha20poly1305-ietf-decrypt-detached-to-buf!
     m
     (bb/->indirect-byte-buf (bb/alloc 0))
     (bb/->indirect-byte-buf c)
     (bb/->indirect-byte-buf mac)
     (bb/->indirect-byte-buf ad)
     (bb/->indirect-byte-buf npub)
     (bb/->indirect-byte-buf k))
    (bb/->bytes m)))
