(ns caesium.vectors
  (:require [caesium.util :as u]
            [clojure.java.io :as io]
            [clojure.string :as s]))

(def hex-resource
  "Gets a named resource in hex format; returns its contents as a byte
  array."
  (comp u/unhexify s/trim slurp io/resource))

(def hex-resources
  "Gets a named resource  in hex format that contains multiple test
  vectors separated by a newline as a collection of byte arrays."
  (comp #(map (comp u/unhexify s/trim) %) #(clojure.string/split % #"\n") slurp io/resource))

(def string-resources
  "Gets a named resource in plain text format that contains multiple test
  vectors separated by a newline as a collection of byte arrays."
  (comp #(map (fn [^String s] (.getBytes s)) %)
        #(clojure.string/split % #"\n") slurp io/resource))
