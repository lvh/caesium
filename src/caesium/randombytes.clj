(ns caesium.randombytes
  "Utilities for producing cryptographically random bytes, suitable
  for use as a key or other input entropy."
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb])
  (:import (java.nio ByteBuffer)))

(defn random-to-buf!
  "**DANGER** This function is low-level, you only want to use it if you are
  managing your own buffers. See [[randombytes]] for a high level API that
  creates the buffer for you.

  Given a byte buffer, populate it with n random bytes.

  If n is not given, populates the entire buffer."
  ([^ByteBuffer buf]
   (random-to-buf! buf (.remaining buf)))
  ([^ByteBuffer buf n]
   (.randombytes b/sodium buf (long n))
   buf))

(defn randombytes
  "Create a byte array with n random bytes."
  [n]
  (bb/->bytes (random-to-buf! (bb/alloc n) n)))
