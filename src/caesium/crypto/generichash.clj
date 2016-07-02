(ns caesium.crypto.generichash
  (:refer-clojure :exclude [bytes hash])
  (:require [caesium.binding :refer [sodium defconsts]]
            [caesium.byte-bufs :refer [buflen]]))

(defconsts [bytes
            bytes-min
            bytes-max
            keybytes
            keybytes-min
            keybytes-max
            blake2b-bytes
            blake2b-bytes-min
            blake2b-bytes-max
            blake2b-keybytes
            blake2b-keybytes-min
            blake2b-keybytes-max
            blake2b-saltbytes
            blake2b-personalbytes])

(defn hash-to-buf!
  "Hashes a message with optional key into a given output buffer using
  libsodium's generichash primitive.

  You only want this to manage the output byte array yourself. Otherwise, you
  want [[hash]]."
  ([buf msg]
   (hash-to-buf! buf msg {}))
  ([buf msg {:keys [key]
             :or {key (byte-array 0)}}]
   (.crypto_generichash
    sodium buf (buflen buf) msg (buflen msg) key (buflen key))))

(defn hash
  "A friendlier API for generichash.

  This is higher-level than [[hash-to-buf!]] because you don't have to
  allocate your own output buffer."
  ([^bytes msg]
   (hash msg {}))
  ([^bytes msg {:keys [size]
                :or {size bytes}
                :as opts}]
   (let [buf (byte-array size)]
     (hash-to-buf! buf msg opts)
     buf)))

(defn blake2b-to-buf!
  ([buf msg]
   (blake2b-to-buf! buf msg {}))
  ([buf msg {:keys [key salt personal]
             :or {key (byte-array 0)}}]
   (if (or salt personal)
     ;; You can't set the defaults in the argspec's destructuring form,
     ;; because you want to be able to differentiate between a salt that
     ;; wasn't passed and an empty salt, to call a different fn.
     (let [salt (or salt (byte-array blake2b-saltbytes))
           personal (or personal (byte-array blake2b-personalbytes))]
       (.crypto_generichash_blake2b_salt_personal
        sodium buf (buflen buf) msg (buflen msg) key (buflen key)
        salt personal))
     (.crypto_generichash_blake2b
      sodium buf (buflen buf) msg (buflen msg) key (buflen key)))
   buf))

(defn blake2b
  ([msg]
   (blake2b msg {}))
  ([msg {:keys [size] :or {size blake2b-bytes} :as opts}]
   (let [buf (byte-array size)]
     (blake2b-to-buf! buf msg opts)
     buf)))
