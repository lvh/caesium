(ns caesium.crypto.box
  "Bindings to the public-key authenticated encryption scheme."
  (:import (org.abstractj.kalium.keys KeyPair
                                      PublicKey
                                      PrivateKey)
           org.abstractj.kalium.crypto.Box))

(defn generate-keypair
  "Generate a secret key and corresponding public key with
  `crypto_box_curve25519xsalsa20poly1305_keypair`.

  If secret key is provided as an argument, generate the corresponding
  public key with `crypto_scalarmult_curve25519`.

  Returns a map containing the public and private key bytes (mutable arrays)."
  ([]
   (let [kp (KeyPair.)]
     {:public (.toBytes (.getPublicKey kp))
      :secret (.toBytes (.getPrivateKey kp))}))
  ([secret-key]
   (let [kp (KeyPair. secret-key)]
     {:public (.toBytes (.getPublicKey kp))
      :secret secret-key})))

(defn encrypt
  "Encrypt with `crypto_box_curve25519xsalsa20poly1305_beforenm` and `crypto_box_curve25519xsalsa20poly1305_afternm`.

  Please note that contrary to Kalium, it only accepts keys in byte array form. It also returns a mutable byte array."
  [^bytes public-key
   ^bytes secret-key
   nonce
   plaintext]
  (let [pbk (PublicKey. public-key)
        pvk (PrivateKey. secret-key)]
    (.encrypt (Box. pbk pvk) nonce plaintext)))

(defn decrypt
  "Decrypt with `crypto_box_curve25519xsalsa20poly1305_beforenm` and `crypto_box_curve25519xsalsa20poly1305_open_afternm`.

  Please note that contrary to Kalium, it only accepts keys in byte
  array form. It also returns a mutable byte array."
  [^bytes public-key
   ^bytes secret-key
   nonce
   ciphertext]
  (let [pbk (PublicKey. public-key)
        pvk (PrivateKey. secret-key)]
    (.decrypt (Box. pbk pvk) nonce ciphertext)))
