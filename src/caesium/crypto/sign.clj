(ns caesium.crypto.sign
  (:import (org.abstractj.kalium.keys SigningKey
                                      VerifyKey)))

(defn generate-signing-keys
  "Generate a public-key and secret-key for signing with `crypto_sign_ed25519_seed_keypair`. If a seed is not provided, one is taken from `randombytes`.

  A map of the secret seed and public-key is returned."
  ([]
   (let [sk (SigningKey.)]
     {:secret (.toBytes sk)
      :public (.toBytes (.getVerifyKey sk))}))
  ([seed]
   (let [sk (SigningKey. seed)]
     {:secret seed
      :public (.toBytes (.getVerifyKey sk))})))

(defn sign
  "Sign a message using `crypto_sign_ed25519`."
  [secret-seed message]
  (.sign (SigningKey. secret-seed) message))

(defn verify
  "Verify a signature using `crypto_sign_ed25519_open`."
  [public-key message signature]
  (.verify (VerifyKey. public-key) message signature))
