(ns caesium.crypto.scalarmult
  "**DANGER** This namespace consists of low-level details that you
  should not use unless you know what you are doing. You probably
  want [[caesium.crypto.box]] instead.

  Scalar multiplication."
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]))

(b/defconsts [bytes scalarbytes primitive])

(defn scalarmult-to-buf!
  "Performs scalar multiplication into the given out buffer against a
  given point using `crypto_scalarmult`, or against the fixed base
  point with `crypto_scalarmult_base` when no point is passed."
  ([q n]
   (b/✨ scalarmult-base q n))
  ([q n p]
   (b/✨ scalarmult q n p)))

(defn scalarmult
  "Performs scalar multiplication against a given point, using"
  ([n]
   (let [q (bb/alloc bytes)]
     (scalarmult-to-buf! q n)
     (bb/->bytes q)))
  ([n p]
   (let [q (bb/alloc bytes)]
     (scalarmult-to-buf! q n p)
     (bb/->bytes q))))
