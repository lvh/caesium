(ns caesium.vectors
  (:require [caesium.util :as u]
            [clojure.java.io :as io]
            [clojure.string :as s]))

(def hex-resource
  "Gets a named resource in hex format; returns its contents as a byte
  array."
  (comp u/unhexify s/trim slurp io/resource))
