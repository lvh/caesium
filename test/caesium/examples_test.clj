(ns caesium.examples-test
  (:require  [clojure.test :refer [deftest]]
             [clojure.java.io :as io]))

(deftest examples-test
  (let [examples (->> (io/file "examples")
                      (file-seq)
                      (filter #(.isFile %)))]
    (doseq [example examples]
      (load-file (.getAbsolutePath example)))))
