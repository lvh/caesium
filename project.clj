(defproject caesium "0.8.0-SNAPSHOT"
  :description "libsodium for clojure"
  :url "https://github.com/lvh/caesium"
  :deploy-repositories [["releases" :clojars]
                        ["snapshots" :clojars]]
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [com.github.jnr/jnr-ffi "2.0.9"]
                 [commons-codec/commons-codec "1.10"]
                 [byte-streams "0.2.2"]
                 [org.clojure/math.combinatorics "0.1.3"]]
  :main ^:skip-aot caesium.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}
             :dev {:source-paths ["src/" "benchmarks/"]
                   :dependencies [[criterium "0.4.4"]]}
             :test {:plugins [[lein-cljfmt "0.3.0"]
                              [lein-kibit "0.1.2"]
                              [jonase/eastwood "0.2.3"]
                              [lein-codox "0.9.4"]
                              [lein-cloverage "1.0.7-SNAPSHOT"]]}
             :benchmarks {:test-paths ^:replace ["benchmarks/"]}}
  :codox {:metadata {:doc/format :markdown}
          :output-path "doc"}
  :global-vars {*warn-on-reflection* true}
  :aliases {"benchmark" ["with-profile" "+benchmarks" "test"]})
