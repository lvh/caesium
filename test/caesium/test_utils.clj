(ns caesium.test-utils)

(defmacro const-test
  [& body]
  (let [exprs (->> (for [[sym val] (partition 2 body)]
                     [`(clojure.test/is (= ~val ~sym))
                      `(clojure.test/is (:const (meta (var ~sym))))])
                   (mapcat identity))]
    `(clojure.test/deftest ~'const-tests
       ~@exprs)))
