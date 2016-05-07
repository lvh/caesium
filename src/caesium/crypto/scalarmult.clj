(ns caesium.crypto.scalarmult
  "**DANGER** This namespace consists of low-level details that you
  should not use unless you know what you are doing. You probably
  want [[caesium.crypto.box]] instead.

  Scalar multiplication."
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :refer [defconsts sodium]]
            [caesium.util :as u]))

(defconsts [bytes scalarbytes primitive])

(defn scalarmult-to-buf!
  "Performs scalar multiplication into the given out buffer against a
  given point using `crypto_scalarmult`, or against the fixed base
  point with `crypto_scalarmult_base` when no point is passed."
  ([n out]
   (.crypto_scalarmult_base sodium out n))
  ([n p out]
   (.crypto_scalarmult sodium out n p)))

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

(def ^bytes int->scalar
  "**DANGER** This fn is typically only used for demos, not secure
  cryptosystems; see rest of docstring for details. Turns an integral
  type (int, bigint, biginteger) into a byte array suitable for use as
  a scalar for scalarmult.

  The resulting byte array will be `scalarbytes` wide.

  Note that int is generally only 32 bits wide (see `Integer/SIZE`),
  whereas scalars here are 32 bytes wide (see `scalarbytes`). An
  attacker can simply exhaust all 32-bit options, so points generated
  this way should not be considered secure."
  (partial u/n->bytes scalarbytes))
