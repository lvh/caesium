(ns caesium.crypto.kdf
  "Deriving keys from a single high-entropy key.

  Multiple secret subkeys can be derived from a single master key.

  Given the master key and a key identifier, a subkey can be deterministically
  computed. However, given a subkey, an attacker cannot compute the master key
  nor any other subkeys.

  The API can derive up to 2^64 keys from a single master key and context, and
  individual subkeys can have an arbitrary length between 128 (16 bytes) and
  512 bits (64 bytes)."
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]))

(b/defconsts [bytes-min bytes-max contextbytes keybytes primitive])

(defn ^:private keygen-to-buf
  [k]
  (b/call! keygen k))

(defn keygen
  "Creates a master key."
  []
  (let [k (bb/alloc keybytes)]
    (keygen-to-buf k)
    (bb/->bytes k)))

(defn ^:private derive-from-key-to-buf!
  [subk subkid ctx k]
  (let [res (b/call! derive-from-key subk subkid ctx k)]
    (when-not (zero? res)
      (throw (RuntimeException. "KDF failed")))))

(defn derive-from-key
  "Derives a `subk-id`-th subkey of length `subk-len` bytes using the master
  key `k` and the context `ctx`.

  `subk-id` can be any integer value up to (2^64)-1.

  `subk-len` has to be between `caesium.crypto.kdf/bytes-min` (inclusive)
  and `caesium.crypto.kdf/bytes-max` (inclusive).

  Similar to a type, the context `ctx` is a 8 characters string describing
  what the key is going to be used for.

  Its purpose is to mitigate accidental bugs by separating domains. The same
  function used with the same key but in two distinct contexts is likely to
  generate two different outputs.
  
  Contexts don't have to be secret and can have a low entropy.

  Examples of contexts include `UserName`, `__auth__`, `pictures` and `userdata`.

  They must be `caesium.crypto.kdf/contextbytes` bytes long.
  
  If more convenient, it is also fine to use a single global context for a whole
  application. This will still prevent the same keys from being mistakenly used
  by another application."
  [subk-len subk-id ctx k]
  (let [subk (bb/alloc subk-len)]
    (derive-from-key-to-buf!
     subk subk-id
     (bb/->indirect-byte-buf ctx)
     (bb/->indirect-byte-buf k))
    (bb/->bytes subk)))

