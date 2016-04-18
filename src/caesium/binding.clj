(ns caesium.binding
  "Bindings to libsodium, using jnr-ffi."
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
;; TODO When does this get called? Guaranteed from 1 thread?

(defn ^:private c-name
  "Resolves the fn name in the current ns to the fn name in the equivalent
  libsodium C pseudo-namespace."
  [^clojure.lang.Namespace namespace ^clojure.lang.Symbol fn-name]
  (let [adjusted-name (-> (name fn-name) (s/replace "-" "_"))
        prefix (-> namespace ns-name str (s/split #"\.") rest vec)
        full-path (conj prefix adjusted-name)]
    (symbol (s/join "_" full-path))))

(defn ^:private java-call-sym
  "Creates the Clojure Java method call syntax to call a method on the
  libsodium binding."
  [c-name]
  (symbol (str "." c-name)))

(defmacro defconsts
  "Given constant names (syms) in the C pseudo-namespace corresponding
  to the current namespace, call the corresponding libsodium function
  the get the constants and assign them to vars."
  [consts]
  `(do ~@(for [const consts
               :let [c-name (c-name *ns* const)]]
           `(def ~const
              (~(java-call-sym c-name) sodium)))))

(defmacro defbindings
  "Creates relevant bindings in the C pseudo-namespace corresponding
  to the current namespace."
  [fs]
  `(do ~@(for [f fs
               :let [c-name (c-name *ns* f)
                     args (->> (bound-fns c-name)
                               (mapv (fn [args] (with-meta args {}))))]]
           `(defn ~f
              ~args
              (~(java-call-sym c-name) sodium ~@args)))))
