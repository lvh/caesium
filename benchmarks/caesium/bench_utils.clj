(ns caesium.bench-utils)

(defn print-title
  [title]
  (println)
  (println title))

(defn fmt-bytes
  [n]
  (reduce (fn [n sym]
            (if (< n 1024)
              (reduced (str n sym))
              (int (/ n 1024))))
          n ["B" "kiB" "MiB" "GiB"]))
