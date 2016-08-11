(ns caesium.crypto.generichash
  (:refer-clojure :exclude [bytes hash])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]
            [medley.core :as m]))

(b/defconsts [bytes
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

  All arguments must be `java.nio.ByteBuffer`.

  You only want this to manage the output buffer yourself. Otherwise,
  you want [[hash]]."
  ([buf msg]
   (hash-to-buf! buf msg {}))
  ([buf msg {:keys [key] :or {key (bb/alloc 0)}}]
   (b/✨ generichash buf msg key)
   buf))

(defn hash
  "Hashes a message with optional key using libsodium's generichash primitive.

  This is higher-level than [[hash-to-buf!]] because you don't have to
  allocate your own output buffer."
  ([msg]
   (hash msg {}))
  ([msg {:keys [size] :or {size bytes} :as opts}]
   (let [buf (bb/alloc size)
         opts (dissoc opts :size)]
     (hash-to-buf!
      buf
      (bb/->indirect-byte-buf msg)
      (m/map-vals bb/->indirect-byte-buf opts))
     (bb/->bytes buf))))

(defn blake2b-to-buf!
  "Hashes a message using BLAKE2b into the given buffer. Optionally
  takes key, salt and personal.

  All arguments must be `java.nio.ByteBuffer`.

  You only want this to manage the output byte buffer yourself. Otherwise, you
  want [[blake2b]]."
  ([buf msg]
   (blake2b-to-buf! buf msg {}))
  ([buf msg {:keys [key salt personal] :or {key (bb/alloc 0)}}]
   (if (or salt personal)
     ;; You can't set the defaults in the argspec's destructuring form,
     ;; because you want to be able to differentiate between a salt that
     ;; wasn't passed and an empty salt, to call a different fn.
     (let [salt (or salt (bb/alloc blake2b-saltbytes))
           personal (or personal (bb/alloc blake2b-personalbytes))]
       (b/✨ blake2b-salt-personal buf msg key salt personal))
     (b/✨ blake2b buf msg key))
   buf))

(defn blake2b
  "Hashes a message using BLAKE2b. Optionally takes key, salt and personal.

  This is higher-level than [[blake2b-to-buf!]] because you don't have to
  allocate your own output buffer."
  ([msg]
   (blake2b msg {}))
  ([msg {:keys [size] :or {size blake2b-bytes} :as opts}]
   (let [buf (bb/alloc size)
         opts (dissoc opts :size)]
     (blake2b-to-buf!
      buf
      (bb/->indirect-byte-buf msg)
      (m/map-vals bb/->indirect-byte-buf opts))
     (bb/->bytes buf))))
