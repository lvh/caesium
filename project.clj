(defproject caesium "0.13.0-SNAPSHOT"
  :description "libsodium for clojure"
  :url "https://github.com/lvh/caesium"
  :deploy-repositories [["releases" :clojars]
                        ["snapshots" :clojars]]
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [com.github.jnr/jnr-ffi "2.1.9"]
                 [commons-codec/commons-codec "1.11"]
                 [byte-streams "0.2.4"]
                 [org.clojure/math.combinatorics "0.1.4"]
                 [medley "1.2.0"]
                 [com.taoensso/timbre "4.10.0"]]
  :main ^:skip-aot caesium.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}
             :dev {:dependencies [[criterium "0.4.5"]
                                  [org.clojure/test.check "0.9.0"]
                                  [com.gfredericks/test.chuck "0.2.10"]]}
             :test {:plugins [[lein-ancient "0.6.15"]
                              [lein-cljfmt "0.6.6"]
                              [lein-kibit "0.1.8"]
                              [jonase/eastwood "0.3.7"]
                              [lein-codox "0.10.7"]
                              [lein-cloverage "1.1.2"]]}
             :benchmarks {:source-paths ["test/"]
                          :test-paths ^:replace ["benchmarks/"]}}
  :codox {:metadata {:doc/format :markdown}
          :output-path "doc"}
  :global-vars {*warn-on-reflection* true}
  :aliases {"benchmark" ["with-profile" "+benchmarks" "test"]})
