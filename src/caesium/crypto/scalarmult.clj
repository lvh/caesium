(ns caesium.crypto.scalarmult
  "**DANGER** This namespace consists of low-level details that you
  should not use unless you know what you are doing. You probably
  want [[caesium.crypto.box]] instead.

  Scalar multiplication."
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :as b]
            [caesium.util :as u]))

(b/defconsts [bytes scalarbytes primitive])

(defn scalarmult-to-buf!
  "Performs scalar multiplication into the given out buffer against a
  given point using `crypto_scalarmult`, or against the fixed base
  point with `crypto_scalarmult_base` when no point is passed."
  ([n out]
   (b/✨ scalarmult-base out n))
  ([n p out]
   (b/✨ scalarmult out n p)))

(defn scalarmult
  "Performs scalar multiplication against a given point, using"
  ([n]
   (let [out (byte-array bytes)]
     (scalarmult-to-buf! n out)
     out))
  ([n p]
   (let [out (byte-array bytes)]
     (scalarmult-to-buf! n p out)
     out)))
