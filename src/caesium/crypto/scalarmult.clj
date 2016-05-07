(ns caesium.crypto.scalarmult
  (:require [caesium.binding :refer [defconsts]]))
  "**DANGER** This namespace consists of low-level details that you
  should not use unless you know what you are doing. You probably
  want [[caesium.crypto.box]] instead.

  Scalar multiplication."

(defconsts [bytes scalarbytes primitive])
