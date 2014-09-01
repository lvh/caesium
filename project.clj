(defproject caesium "0.1.2-SNAPSHOT"
  :description "libsodium for clojure"
  :url "https://github.com/lvh/caesium"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.abstractj.kalium/kalium "0.2.1" :scope "compile"]]
  :main ^:skip-aot caesium.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
