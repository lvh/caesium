(ns caesium.byte-bufs
  "Byte buffer utilities, like conversions and length."
  (:require [byte-streams :as bs])
  (:import (java.nio ByteBuffer)))

(defn ->indirect-byte-buf
  [x]
  (bs/convert x ByteBuffer {:direct? false}))

(defn ->direct-byte-buf
  [x]
  (bs/convert x ByteBuffer {:direct? true}))

(defprotocol BufLen
  (^Long buflen [this]))

(extend-protocol BufLen
  (Class/forName "[B")
  (buflen [this] (alength ^bytes this))

  ByteBuffer
  (buflen [this] (.remaining ^ByteBuffer this)))
