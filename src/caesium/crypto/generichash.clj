(ns caesium.crypto.generichash
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :refer [sodium defconsts defbindings]]))

(defconsts [bytes bytes-min bytes-max keybytes keybytes-min keybytes-max])
(defbindings [generichash])
