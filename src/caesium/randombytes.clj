(ns caesium.randombytes
  "Utilities for producing cryptographically random bytes, suitable
  for use as a key or other input entropy."
  (:require [caesium.binding :refer [sodium]]
            [caesium.byte-bufs :refer [buflen]])
  (:import (java.nio ByteBuffer)))

(defn random-to-byte-array!
  "**DANGER** This function is low-level, you only want to use it if you are
  managing your own buffers. See [[randombytes]] for a high level API that
  creates the byte array buffer for you.

  Given a byte array, populate it with n random bytes.

  If n is not given, populates the entire array."
  ([^bytes arr]
   (random-to-byte-array! arr (buflen arr)))
  ([^bytes arr n]
   (.randombytes sodium arr (long n))
   arr))

(defn random-to-byte-buffer!
  "**DANGER** This function is low-level, you only want to use it if you are
  managing your own buffers. See [[randombytes]] for a high level API that
  creates the byte array buffer for you.

  Given a byte buffer, populate it with n random bytes.

  If n is not given, populates the entire buffer."
  ([^ByteBuffer buf]
   (random-to-byte-buffer! buf (.remaining buf)))
  ([^ByteBuffer buf n]
   (.randombytes sodium buf (long n))
   buf))

(defn randombytes
  "Create a byte array with n random bytes."
  [n]
  (let [buf (byte-array n)]
    (random-to-byte-array! buf n)))
