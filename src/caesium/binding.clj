(ns caesium.binding
  "**DANGER** These are the low-level bindings to libsodium, using
  jnr-ffi. They are probably not what you want; instead, please look at
  the [[caesium.crypto.box]], [[caesium.crypto.secretbox]],
  [[caesium.crypto.generichash]], [[caesium.crypto.sign]]  et cetera,
  namespaces."
  (:require [clojure.string :as s]
            [clojure.math.combinatorics :as c]
            [medley.core :as m]
            [clojure.string :as str])
  (:import [jnr.ffi LibraryLoader]
           [jnr.ffi.annotations In Out Pinned LongLong]
           [jnr.ffi.types size_t]))

(def ^:private bound-byte-type-syms
  '[bytes java.nio.ByteBuffer])

(defn ^:private permuted-byte-types
  "Given a method signature, return signatures for all bound byte types.

  Signature should be as per [[bound-fns]], with byte arguments annotated with
  `{:tag 'bytes}` in their metadata (note: the symbol, not the fn)."
  [[name args]]
  (let [byte-args (filter #(= (:tag (meta %)) 'bytes) args)]
    (for [types (c/selections bound-byte-type-syms (count byte-args))
          :let [arg->type (zipmap byte-args types)
                ann (fn [arg]
                      (let [tag (get arg->type arg (:tag (meta arg)))]
                        (vary-meta arg assoc :tag tag)))]]
      [name (mapv ann args)])))

(def ^:private raw-bound-fns
  "See [[bound-fns]], but without the permutations."
  '[[^int sodium_init []]
     [^String sodium_version_string []]

     [^void randombytes
      [^bytes ^{Pinned {}} buf
       ^long ^{LongLong {}} buflen]]

     [^long ^{size_t {}} crypto_secretbox_keybytes []]
     [^long ^{size_t {}} crypto_secretbox_noncebytes []]
     [^long ^{size_t {}} crypto_secretbox_macbytes []]
     [^String crypto_secretbox_primitive []]
     [^int crypto_secretbox_easy
      [^bytes ^{Pinned {}} c
       ^bytes ^{Pinned {}} m
       ^long ^{LongLong {}} mlen
       ^bytes ^{Pinned {}} n
       ^bytes ^{Pinned {}} k]]
     [^int crypto_secretbox_open_easy
      [^bytes ^{Pinned {}} m
       ^bytes ^{Pinned {}} c
       ^long ^{LongLong {}} clen
       ^bytes ^{Pinned {}} n
       ^bytes ^{Pinned {}} k]]
     [^int crypto_secretbox_detached
      [^bytes ^{Pinned {}} c
       ^bytes ^{Pinned {}} mac
       ^bytes ^{Pinned {}} m
       ^long ^{LongLong {}} mlen
       ^bytes ^{Pinned {}} n
       ^bytes ^{Pinned {}} k]]
     [^int crypto_secretbox_open_detached
      [^bytes ^{Pinned {}} m
       ^bytes ^{Pinned {}} c
       ^bytes ^{Pinned {}} mac
       ^long ^{LongLong {}} clen
       ^bytes ^{Pinned {}} n
       ^bytes ^{Pinned {}} k]]

     [^long ^{size_t {}} crypto_box_seedbytes []]
     [^long ^{size_t {}} crypto_box_publickeybytes []]
     [^long ^{size_t {}} crypto_box_secretkeybytes []]
     [^long ^{size_t {}} crypto_box_noncebytes []]
     [^long ^{size_t {}} crypto_box_macbytes []]
     [^String ^{size_t {}} crypto_box_primitive []]

     [^int crypto_box_seed_keypair
      [^bytes ^{Pinned {}} pk
       ^bytes ^{Pinned {}} sk
       ^bytes ^{Pinned {}} seed]]
     [^int crypto_box_keypair
      [^bytes ^{Pinned {}} pk
       ^bytes ^{Pinned {}} sk]]
     [^int crypto_box_easy
      [^bytes ^{Pinned {}} c
       ^bytes ^{Pinned {}} m
       ^long ^{LongLong {}} mlen
       ^bytes ^{Pinned {}} n
       ^bytes ^{Pinned {}} pk
       ^bytes ^{Pinned {}} sk]]
     [^int crypto_box_open_easy
      [^bytes ^{Pinned {}} m
       ^bytes ^{Pinned {}} c
       ^long ^{LongLong {}} clen
       ^bytes ^{Pinned {}} n
       ^bytes ^{Pinned {}} pk
       ^bytes ^{Pinned {}} sk]]

     [^long ^{size_t {}} crypto_sign_bytes []]
     [^long ^{size_t {}} crypto_sign_seedbytes []]
     [^long ^{size_t {}} crypto_sign_publickeybytes []]
     [^long ^{size_t {}} crypto_sign_secretkeybytes []]
     [^String crypto_sign_primitive []]

     [^int crypto_sign_keypair
      [^bytes ^{Pinned {}} pk
       ^bytes ^{Pinned {}} sk]]
     [^int crypto_sign_seed_keypair
      [^bytes ^{Pinned {}} pk
       ^bytes ^{Pinned {}} sk
       ^bytes ^{Pinned {}} seed]]
     [^int crypto_sign
      [^bytes ^{Pinned {}} sm
       ^jnr.ffi.byref.LongLongByReference smlen_p
       ^bytes ^{Pinned {}} m
       ^long ^{LongLong {}} mlen
       ^bytes ^{Pinned {}} sk]]
     [^int crypto_sign_open
      [^bytes ^{Pinned {}} m
       ^jnr.ffi.byref.LongLongByReference mlen_p
       ^bytes ^{Pinned {}} sm
       ^long ^{LongLong {}} smlen
       ^bytes ^{Pinned {}} pk]]
     [^int crypto_sign_detached
      [^bytes ^{Pinned {}} sig
       ^jnr.ffi.byref.LongLongByReference siglen_p
       ^bytes ^{Pinned {}} m
       ^long ^{LongLong {}} mlen
       ^bytes ^{Pinned {}} sk]]
     [^int crypto_sign_verify_detached
      [^bytes ^{Pinned {}} sig
       ^bytes ^{Pinned {}} m
       ^long ^{LongLong {}} mlen
       ^bytes ^{Pinned {}} pk]]

     [^long ^{size_t {}} crypto_generichash_bytes_min []]
     [^long ^{size_t {}} crypto_generichash_bytes_max []]
     [^long ^{size_t {}} crypto_generichash_bytes []]
     [^long ^{size_t {}} crypto_generichash_keybytes_min []]
     [^long ^{size_t {}} crypto_generichash_keybytes_max []]
     [^long ^{size_t {}} crypto_generichash_keybytes []]
     [^String crypto_generichash_primitive []]
     [^int crypto_generichash
      [^bytes ^{Pinned {}} buf
       ^long ^{LongLong {}} buflen
       ^bytes ^{Pinned {}} msg
       ^long ^{LongLong {}} msglen
       ^bytes ^{Pinned {}} key
       ^long ^{LongLong {}} keylen]]

     [^long ^{size_t {}} crypto_generichash_blake2b_bytes_min []]
     [^long ^{size_t {}} crypto_generichash_blake2b_bytes_max []]
     [^long ^{size_t {}} crypto_generichash_blake2b_bytes []]
     [^long ^{size_t {}} crypto_generichash_blake2b_keybytes_min []]
     [^long ^{size_t {}} crypto_generichash_blake2b_keybytes_max []]
     [^long ^{size_t {}} crypto_generichash_blake2b_keybytes []]
     [^long ^{size_t {}} crypto_generichash_blake2b_saltbytes []]
     [^long ^{size_t {}} crypto_generichash_blake2b_personalbytes []]
     [^long ^{size_t {}} crypto_generichash_blake2b_statebytes []]
     [^int crypto_generichash_blake2b
      [^bytes ^{Pinned {}} buf
       ^long ^{LongLong {}} buflen
       ^bytes ^{Pinned {}} msg
       ^long ^{LongLong {}} msglen
       ^bytes ^{Pinned {}} key
       ^long ^{LongLong {}} keylen]]
     [^int crypto_generichash_blake2b_salt_personal
      [^bytes ^{Pinned {}} buf
       ^long ^{LongLong {}} buflen
       ^bytes ^{Pinned {}} msg
       ^long ^{LongLong {}} msglen
       ^bytes ^{Pinned {}} key
       ^long ^{LongLong {}} keylen
       ^bytes ^{Pinned {}} salt
       ^bytes ^{Pinned {}} personal]]

     [^long ^{size_t {}} crypto_hash_sha256_bytes []]
     [^int crypto_hash_sha256
      [^bytes ^{Pinned {}} buf
       ^bytes ^{Pinned {}} msg
       ^long ^{LongLong {}} msglen]]

     [^long ^{size_t {}} crypto_hash_sha512_bytes []]
     [^int crypto_hash_sha512
      [^bytes ^{Pinned {}} buf
       ^bytes ^{Pinned {}} msg
       ^long ^{LongLong {}} msglen]]

     [^long ^{size_t {}} crypto_scalarmult_bytes []]
     [^long ^{size_t {}} crypto_scalarmult_scalarbytes []]
     [^String crypto_scalarmult_primitive []]

     [^int crypto_scalarmult_base
      [^bytes ^{Pinned {}} q
       ^bytes ^{Pinned {}} n]]
     [^int crypto_scalarmult
      [^bytes ^{Pinned {}} q
       ^bytes ^{Pinned {}} n
       ^bytes ^{Pinned {}} p]]])

(def ^:private bound-fns
  "A mapping of type- and jnr.ffi-annotated bound method symbols to
  respective argspec.

  This exists so that tooling (like magic macro helpers) can easily
  inspect caesium allegedly binds. That can be done by reflecting on
  the interface too, but that's significantly less convenient;
  Clojure's reflection tools don't show annotations, and we always use
  the data in metadata-annotated form anyway (both to create the
  interface and to bind fns to vars).

  This has to be a vec and not a map, because the same key (symbol,
  method name) might occur with multiple values (e.g. when binding the
  same char* fn with different JVM byte types)."
  (mapcat permuted-byte-types raw-bound-fns))

(defmacro ^:private defsodium
  []
  `(definterface ~'Sodium ~@bound-fns))

(defsodium)

(def ^Sodium sodium
  "The sodium library singleton instance."
  (let [loader (LibraryLoader/create Sodium)]
    (.load loader "sodium")))

(assert (#{0 1} (.sodium_init sodium)))
;; TODO When does this get called? Guaranteed from 1 thread?

(defn ^:private c-name
  "Resolves the fn name in the current ns to the fn name in the equivalent
  libsodium C pseudo-namespace."
  [^clojure.lang.Namespace namespace ^clojure.lang.Symbol fn-name]
  (let [fn-name (-> (name fn-name) (s/replace "-" "_"))
        prefix (-> namespace ns-name str (s/split #"\.") rest vec)
        path (into prefix (when-not (= (last prefix) fn-name) [fn-name]))]
    (symbol (s/join "_" path))))

(defn ^:private java-call-sym
  "Creates the Clojure Java method call syntax to call a method on the
  libsodium binding."
  [c-name]
  (symbol (str "." c-name)))

(defmacro defconsts
  "Define a number of constants by name.

  Uses the *ns* to figure out the const-returning fn in libsodium."
  [consts]
  `(do ~@(for [const consts
               :let [c-name (c-name *ns* const)
                     docstring (str "Constant returned by `" c-name "`. "
                                    "See libsodium docs.")]]
           `(def ~(with-meta const {:const true})
              ~docstring
              (~(java-call-sym c-name) sodium)))))

(defmacro ✨
  "Produces a form for calling named fn with lots of magic:

  * The fn-name is specified using its short name, which is resolved
    against the ns as per [[defconsts]].
  * All bufs are annotated as ByteBuffers.
  * Buffer lengths are automatically added.

  The emoji name of this macro accurately reflects how easy I want it
  to be for third parties to call it."
  [fn-name & args]
  (let [c-name (c-name *ns* fn-name)
        call-sym (java-call-sym c-name)
        [_ argdefs] (m/find-first
                     (fn [[name _]] (= name c-name))
                     raw-bound-fns)
        real-tag {'bytes 'java.nio.ByteBuffer}
        tag (fn [arg] (-> (m/find-first (partial = arg) argdefs)
                          meta :tag real-tag))
        hinted (fn [sym] (with-meta sym {:tag (tag sym)}))
        len-of (fn [sym]
                 (let [obj-sym (symbol (str/replace (name sym) #"len$" ""))]
                   `(long (caesium.byte-bufs/buflen ~obj-sym))))
        computed-args (for [arg argdefs
                            :let [f (if (some #{arg} args) hinted len-of)]]
                        (f arg))]
    `(~call-sym sodium ~@computed-args)))
