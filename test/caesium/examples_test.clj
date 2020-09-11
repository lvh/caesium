(ns caesium.examples-test
  (:require  [clojure.test :refer [deftest]]
             [clojure.java.io :as io]))

(deftest examples-test
  (let [examples (->> (io/file "examples")
                      (file-seq)
                      (filter #(.isFile ^java.io.File %)))]
    (doseq [^java.io.File example examples]
      (load-file (.getAbsolutePath example)))))
