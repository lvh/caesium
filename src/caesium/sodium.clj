(ns caesium.sodium
  "Bindings for sodium_* functions."
  (:require [caesium.binding :refer [sodium]]))

(defn init
  "Initializes libsodium.

  This should be called once, when your application starts. It is
  idempotent: calling it doesn't do anything if it had already been
  called. It is *not* thread-safe (until it has completed once): if
  you call it in thread A, you can't concurrently call it in thread B,
  until it finishes executing in thread A. Usually this is not a
  problem: just run it synchronously in your application's init
  routine."
  []
  (.sodium_init sodium))
