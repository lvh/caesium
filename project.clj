(defproject caesium "0.3.0"
  :description "libsodium for clojure"
  :url "https://github.com/lvh/caesium"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.abstractj.kalium/kalium "0.4.0" :scope "compile"]]
  :main ^:skip-aot caesium.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}}
  :global-vars {*warn-on-reflection* true})
