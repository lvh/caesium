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
  "Computes the scalar multiplication of a point into the given output
  buffer. If no point is specified, the standard base point of the
  curve is used."
  ([q n]
   (b/magic-sparkles scalarmult-base q n))
  ([q n p]
   (b/magic-sparkles scalarmult q n p)))

(defn scalarmult
  "Computes the scalar multiplication of a point. If no point is
  specified, the standard base point of the curve is used."
  ([n]
   (let [q (bb/alloc bytes)]
     (scalarmult-to-buf! q (bb/->indirect-byte-buf n))
     (bb/->bytes q)))
  ([n p]
   (let [q (bb/alloc bytes)]
     (scalarmult-to-buf!
      q (bb/->indirect-byte-buf n) (bb/->indirect-byte-buf p))
     (bb/->bytes q))))
