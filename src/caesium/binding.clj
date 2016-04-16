(ns caesium.binding
  (:require [clojure.string :as s])
  (:import [jnr.ffi LibraryLoader]
           [jnr.ffi.annotations In Out Pinned LongLong]
           [jnr.ffi.types size_t]))

(def ^:private bound-fns
  "A mapping of type- and jnr.ffi-annotated bound method symbols to
  respective argspec.

  This exists so that tooling (like magic macro helpers) can easily
  inspect caesium allegedly binds. That can be done by reflecting on
  the interface too, but that's significantly less convenient;
  Clojure's reflection tools don't show annotations, and we always use
  the data in metadata-annotated form anyway (both to create the
  interface and to bind fns to vars)."
  '{^int sodium_init []
    ^String sodium_version_string []

    ^void randombytes
    [^bytes ^{Pinned {}} buf
     ^long ^{LongLong {}} buflen]

    ^long ^{size_t {}} crypto_secretbox_keybytes []
    ^long ^{size_t {}} crypto_secretbox_noncebytes []
    ^long ^{size_t {}} crypto_secretbox_macbytes []
    ^String ^{size_t {}} crypto_secretbox_primitive[]

    ^int crypto_secretbox_easy
    [^bytes ^{Pinned {}} c
     ^bytes ^{Pinned {}} m
     ^long ^{LongLong {}} mlen
     ^bytes ^{Pinned {}} n
     ^bytes ^{Pinned {}} k]
    ^int crypto_secretbox_open_easy
    [^bytes ^{Pinned {}} m
     ^bytes ^{Pinned {}} c
     ^long ^{LongLong {}} clen
     ^bytes ^{Pinned {}} n
     ^bytes ^{Pinned {}} k]
    ^int crypto_secretbox_detached
    [^bytes ^{Pinned {}} c
     ^bytes ^{Pinned {}} mac
     ^bytes ^{Pinned {}} m
     ^long ^{LongLong {}} mlen
     ^bytes ^{Pinned {}} n
     ^bytes ^{Pinned {}} k]
    ^int crypto_secretbox_open_detached
    [^bytes ^{Pinned {}} m
     ^bytes ^{Pinned {}} c
     ^bytes ^{Pinned {}} mac
     ^long ^{LongLong {}} clen
     ^bytes ^{Pinned {}} n
     ^bytes ^{Pinned {}} k]

    ^long ^{size_t {}} crypto_generichash_bytes_min []
    ^long ^{size_t {}} crypto_generichash_bytes_max []
    ^long ^{size_t {}} crypto_generichash_bytes []
    ^long ^{size_t {}} crypto_generichash_keybytes_min []
    ^long ^{size_t {}} crypto_generichash_keybytes_max []
    ^long ^{size_t {}} crypto_generichash_keybytes []
    ^String crypto_generichash_primitive []
    ^int crypto_generichash
    [^bytes ^{Pinned {}} buf
     ^long ^{LongLong {}} buflen
     ^bytes ^{Pinned {}} msg
     ^long ^{LongLong {}} msglen
     ^bytes ^{Pinned {}} key
     ^long ^{LongLong {}} keylen]

    ;; TODO: how do I reference a crypto_generichash_state *?

    ^int crypto_hash_sha256_bytes []
    ^int crypto_hash_sha256
    [^bytes ^{Pinned {}} buf
     ^bytes ^{Pinned {}} msg
     ^long ^{LongLong {}} msglen]

    ^int crypto_hash_sha512_bytes []
    ^int crypto_hash_sha512
    [^bytes ^{Pinned {}} buf
     ^bytes ^{Pinned {}} msg
     ^long ^{LongLong {}} msglen]})

(defmacro ^:private defsodium
  []
  `(definterface ~'Sodium ~@(seq bound-fns)))

(defsodium)

(def ^Sodium sodium
  "The sodium library singleton instance."
  (let [loader (LibraryLoader/create Sodium)]
    (.load loader "sodium")))

(assert (#{0 1} (.sodium_init sodium)))

(defmacro defconsts
  "Given constant names (syms) in the C pseudo-namespace corresponding
  to the current namespace, call the corresponding libsodium function
  the get the constants and assign them to vars."
  [consts]
  (let [prefix (-> *ns* ns-name str (s/split #"\.") rest vec)]
    `(do
       ~@(for [const consts]
           (let [name (-> const name (s/replace "-" "_") symbol)
                 call (->> name (conj (prefix)) (s/join "_") (str ".") symbol)]
             `(def ~const (~call sodium)))))))


;; int crypto_generichash(unsigned char *out, size_t outlen,
;;                                 const unsigned char *in, unsigned long long inlen,
;;                                 const unsigned char *key, size_t keylen);

;; SODIUM_EXPORT
;; int crypto_generichash_init(crypto_generichash_state *state,
;;                                                      const unsigned char *key,
;;                                                      const size_t keylen, const size_t outlen);

;; SODIUM_EXPORT
;; int crypto_generichash_update(crypto_generichash_state *state,
;;                                                        const unsigned char *in,
;;                                                        unsigned long long inlen);

;; SODIUM_EXPORT
;; int crypto_generichash_final(crypto_generichash_state *state,
;;                                                       unsigned char *out, const size_t outlen);
