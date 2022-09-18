(defproject caesium "0.15.0-SNAPSHOT"
  :description "libsodium for clojure"
  :url "https://github.com/lvh/caesium"
  :deploy-repositories [["releases" {:url "https://repo.clojars.org"
                                     :creds :gpg}]
                        ["snapshots" {:url "https://repo.clojars.org"
                                      :creds :gpg}]]
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [com.github.jnr/jnr-ffi "2.2.12"]
                 [commons-codec/commons-codec "1.15"]
                 [byte-streams "0.2.4"]
                 [org.clojure/math.combinatorics "0.1.6"]
                 [medley "1.4.0"]
                 [com.taoensso/timbre "5.2.1"]]
  :main ^:skip-aot caesium.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}
             :dev {:dependencies [[criterium "0.4.6"]
                                  [org.clojure/test.check "1.1.1"]
                                  [com.gfredericks/test.chuck "0.2.13"]]}
             :test {:plugins [[lein-ancient "0.7.0"]
                              [lein-cljfmt "0.9.0"]
                              [lein-kibit "0.1.8"]
                              [jonase/eastwood "1.3.0"]
                              [lein-codox "0.10.8"]
                              [lein-cloverage "1.2.4"]]
                    :eastwood {:config-files ["eastwood.clj"]}}
             :benchmarks {:source-paths ["test/"]
                          :test-paths ^:replace ["benchmarks/"]}}
  :codox {:metadata {:doc/format :markdown}
          :output-path "doc"}
  :global-vars {*warn-on-reflection* true}
  :aliases {"benchmark" ["with-profile" "+benchmarks" "test"]})
