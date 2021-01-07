(ns caesium.crypto.core.ristretto255
  "**DANGER** This namespace consists of low-level details that you
  should not use unless you know what you are doing. You probably
  want [[caesium.crypto.box]] instead.

  Primitive operations on Ristretto255."
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]))

(declare bytes hashbytes scalarbytes nonreducedscalarbytes)
(b/defconsts [bytes hashbytes scalarbytes nonreducedscalarbytes])

(defn ^:private valid-point-in-buf?
  [p]
  (let [res (b/call! is_valid_point p)]
    (if (zero? res)
      false
      true)))

(defn valid-point?
  "Checks that `p` is a valid ristretto255-encoded element.
  
  This operation only checks that `p` is in canonical form.

  Returns `true` on success, and `false` if the checks didn't pass."
  [p]
  (valid-point-in-buf? (bb/->indirect-byte-buf p)))

(defn ^:private add-to-buf!
  [r p q]
  (let [res (b/call! add r p q)]
    (when-not (zero? res)
      (throw (RuntimeException. "`p` and/or `q` are not valid encoded elements")))))

(defn add
  "Adds the element represented by `p` to the element `q` and
  returns the resulting element.

  If `p` and/or `q` are not valid encoded elements, raises RuntimeException."
  [p q]
  (let [r (bb/alloc bytes)]
    (add-to-buf! r (bb/->indirect-byte-buf p) (bb/->indirect-byte-buf q))
    (bb/->bytes r)))

(defn ^:private sub-to-buf!
  [r p q]
  (let [res (b/call! sub r p q)]
    (when-not (zero? res)
      (throw (RuntimeException. "`p` and/or `q` are not valid encoded elements")))))

(defn sub
  "Substracts the element represented by `p` to the element `q` and
  returns the resulting element.

  If `p` and/or `q` are not valid encoded elements, raises RuntimeException."
  [p q]
  (let [r (bb/alloc bytes)]
    (sub-to-buf! r (bb/->indirect-byte-buf p) (bb/->indirect-byte-buf q))
    (bb/->bytes r)))

(defn ^:private hash->group-to-buf
  [p r]
  (b/call! from-hash p r))

(defn hash->group
  "Maps a 64 bytes vector `r` (usually the output of a hash function)
  to a group element, and returns its representation."
  [r]
  (let [p (bb/alloc bytes)]
    (hash->group-to-buf p (bb/->indirect-byte-buf r))
    (bb/->bytes p)))

(defn ^:private random-to-buf
  [p]
  (b/call! random p))

(defn random
  "Returns the representation of a random group element."
  []
  (let [p (bb/alloc bytes)]
    (random-to-buf p)
    (bb/->bytes p)))
