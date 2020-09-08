(ns caesium.crypto.core.ristretto255.scalar
  "**DANGER** This namespace consists of low-level details that you
  should not use unless you know what you are doing. You probably
  want [[caesium.crypto.box]] instead.

  Scalar operations on Ristretto255."
  (:refer-clojure :exclude [bytes reduce complement])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]
            [caesium.crypto.core.ristretto255 :refer [scalarbytes]]))

(defn ^:private random-to-buf
  [r]
  (b/call! random r))

(defn random
  "Scalars should ideally be randomly chosen in the `[0..L[` interval,
  `L` being the order of the group (2^252 + 27742317777372353535851937790883648493).

  This function returns a `caesium.crypto.core.ristretto255/scalarbytes` bytes
  representation of the scalar in the `]0..L[` interval."
  []
  (let [r (bb/alloc scalarbytes)]
    (random-to-buf r)
    (bb/->bytes r)))

(defn invert-to-buf!
  [recip s]
  (let [res (b/call! invert recip s)]
    (when-not (zero? res)
      (throw
       (RuntimeException. "Failed to calculate the multiplicative inverse of a zero")))))

(defn invert
  "Computes and returns the multiplicative inverse of `s` over L,
  `L` being the order of the group (2^252 + 27742317777372353535851937790883648493).

  If `s` is zero, raises RuntimeException."
  [s]
  (let [recip (bb/alloc scalarbytes)]
    (invert-to-buf! recip (bb/->indirect-byte-buf s))
    (bb/->bytes recip)))

(defn ^:private negate-to-buf
  [neg s]
  (b/call! negate neg s))

(defn negate
  "Returns `neg` so that `s + neg = 0 (mod L)`,
  `L` being the order of the group (2^252 + 27742317777372353535851937790883648493)."
  [s]
  (let [neg (bb/alloc scalarbytes)]
    (negate-to-buf neg (bb/->indirect-byte-buf s))
    (bb/->bytes neg)))

(defn ^:private complement-to-buf
  [result s]
  (b/call! complement result s))

(defn complement
  "Returns `comp` so that `s + comp = 1 (mod L)`,
  `L` being the order of the group (2^252 + 27742317777372353535851937790883648493)."
  [s]
  (let [result (bb/alloc scalarbytes)]
    (complement-to-buf result (bb/->indirect-byte-buf s))
    (bb/->bytes result)))

(defn ^:private add-to-buf
  [z x y]
  (b/call! add z x y))

(defn add
  "Returns `x + y (mod L)`, `L` being the order of the group
  (2^252 + 27742317777372353535851937790883648493)."
  [x y]
  (let [z (bb/alloc scalarbytes)]
    (add-to-buf z (bb/->indirect-byte-buf x) (bb/->indirect-byte-buf y))
    (bb/->bytes z)))

(defn ^:private sub-to-buf
  [z x y]
  (b/call! sub z x y))

(defn sub
  "Returns `x - y (mod L)`, `L` being the order of the group
  (2^252 + 27742317777372353535851937790883648493)."
  [x y]
  (let [z (bb/alloc scalarbytes)]
    (sub-to-buf z (bb/->indirect-byte-buf x) (bb/->indirect-byte-buf y))
    (bb/->bytes z)))

(defn ^:private mul-to-buf
  [z x y]
  (b/call! mul z x y))

(defn mul
  "Returns `x * y (mod L)`, `L` being the order of the group
  (2^252 + 27742317777372353535851937790883648493)."
  [x y]
  (let [z (bb/alloc scalarbytes)]
    (mul-to-buf z (bb/->indirect-byte-buf x) (bb/->indirect-byte-buf y))
    (bb/->bytes z)))

(defn ^:private reduce-to-buf
  [r s]
  (b/call! reduce r s))

(defn reduce
  "A scalar in the `[0..L[` interval can also be obtained by reducing
  a possibly larger value `s`.

  This function reduces `s` to `s mod L` and returns the
  `caesium.crypto.core.ristretto255/scalarbytes` bytes of the
  resulting integer."
  [s]
  (let [r (bb/alloc scalarbytes)]
    (reduce-to-buf r (bb/->indirect-byte-buf s))
    (bb/->bytes r)))

(defn ^:private canonical-in-buf?
  [s]
  (if (b/call! is_canonical s)
    true
    false))

(defn canonical?
  "Checks if `s` is a canonical form and returns `true` if so,
  and `false` otherwise."
  [s]
  (canonical-in-buf? (bb/->indirect-byte-buf s)))
