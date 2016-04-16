(ns caesium.crypto.hash
  (:require [caesium.binding :refer [sodium defconsts defbindings]]))

(defconsts [sha256-bytes sha512-bytes])
(defbindings [sha256 sha512])
