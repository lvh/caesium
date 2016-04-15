(ns caesium.randombytes
  (:require [caesium.binding :refer [sodium]]))

(defn randombytes
  [n]
  (let [buf (byte-array n)]
    (.randombytes sodium buf n)
    buf))
