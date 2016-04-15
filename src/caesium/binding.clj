(ns caesium.binding
  (:require [clojure.string :as s])
  (:import [jnr.ffi LibraryLoader]
           [jnr.ffi.annotations In Out Pinned LongLong]
           [jnr.ffi.types size_t]))

(definterface Sodium
  (^int sodium_init [])
  (^String sodium_version_string [])

  (^void randombytes
   [^bytes ^{Pinned {}} buf
    ^long ^{LongLong {}} buflen])

  (^long ^{size_t {}} crypto_secretbox_keybytes [])
  (^long ^{size_t {}} crypto_secretbox_noncebytes [])
  (^long ^{size_t {}} crypto_secretbox_macbytes [])
  (^String ^{size_t {}} crypto_secretbox_primitive[])

  (^long ^{size_t {}} crypto_generichash_bytes_min [])
  (^long ^{size_t {}} crypto_generichash_bytes_max [])
  (^long ^{size_t {}} crypto_generichash_bytes [])
  (^long ^{size_t {}} crypto_generichash_keybytes_min [])
  (^long ^{size_t {}} crypto_generichash_keybytes_max [])
  (^long ^{size_t {}} crypto_generichash_keybytes [])
  (^String crypto_generichash_primitive [])
  (^int crypto_generichash
   [^bytes ^{Pinned {}} buf
    ^long ^{LongLong {}} buflen
    ^bytes ^{Pinned {}} msg
    ^long ^{LongLong {}} msglen
    ^bytes ^{Pinned {}} key
    ^long ^{LongLong {}} keylen])

  ;; TODO: how do I reference a crypto_generichash_state *?

  (^int crypto_hash_sha256_bytes [])
  (^int crypto_hash_sha256
   [^bytes ^{Pinned {}} buf
    ^bytes ^{Pinned {}} msg
    ^long ^{LongLong {}} msglen])

  (^int crypto_hash_sha512_bytes [])
  (^int crypto_hash_sha512
   [^bytes ^{Pinned {}} buf
    ^bytes ^{Pinned {}} msg
    ^long ^{LongLong {}} msglen]))

(def ^Sodium sodium
  (let [loader (LibraryLoader/create Sodium)]
    (.load loader "sodium")))

(assert (#{0 1} (.sodium_init sodium)))

(defmacro defconsts
  [consts]
  (let [prefix (-> *ns* ns-name str (s/split #"\.") rest vec)]
    `(do
       ~@(for [const consts]
           (let [name (-> const name (s/replace "-" "_") symbol)
                 call (->> name (conj prefix) (s/join "_") (str ".") symbol)]
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
