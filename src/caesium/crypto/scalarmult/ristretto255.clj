(ns caesium.crypto.scalarmult.ristretto255
  "**DANGER** This namespace consists of low-level details that you
  should not use unless you know what you are doing. You probably
  want [[caesium.crypto.box]] instead.

  Scalar multiplication on Ristretto255."
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]))

(b/defconsts [bytes scalarbytes])

(defn scalarmult-to-buf!
  "Computes the scalar multiplication of a point into the given output
  buffer. If no point is specified, the standard base point of the
  curve is used."
  ([q n]
   (let [res (b/call! base q n)]
     (when-not (zero? res)
      (throw (RuntimeException. "scalarmult failed")))))
  ([q n p]
   (let [res (b/call! ristretto255 q n p)]
     (when-not (zero? res)
      (throw (RuntimeException. "scalarmult failed"))))))

(defn scalarmult
  "Computes the scalar multiplication of a point. If no point is
  specified, the standard base point of the curve is used.

  If multiplication fails, raises RuntimeException."
  ([n]
   (let [q (bb/alloc bytes)]
     (scalarmult-to-buf! q (bb/->indirect-byte-buf n))
     (bb/->bytes q)))
  ([n p]
   (let [q (bb/alloc bytes)]
     (scalarmult-to-buf!
      q (bb/->indirect-byte-buf n) (bb/->indirect-byte-buf p))
     (bb/->bytes q))))
