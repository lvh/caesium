(ns caesium.crypto.box
  "Bindings to the public-key authenticated encryption scheme."
  (:import (org.abstractj.kalium.keys PublicKey
                                      PrivateKey)
           org.abstractj.kalium.crypto.Box))

(defn encrypt
  "Encrypt with `crypto_box_easy`.

  Please note that contrary to Kalium, it only accepts keys in byte array form. It also returns a mutable byte array."
  [^bytes public-key
   ^bytes private-key
   nonce
   plaintext]
  (let [pbk (PublicKey. public-key)
        pvk (PrivateKey. private-key)]
    (.encrypt (Box. pbk pvk) nonce plaintext)))

(defn decrypt
  "Decrypt with `crypto_box_easy_open`.

  Please note that contrary to Kalium, it only accepts keys in byte array form. It also returns a mutable byte array."
  [^bytes public-key
   ^bytes private-key
   nonce
   ciphertext]
  (let [pbk (PublicKey. public-key)
        pvk (PrivateKey. private-key)]
    (.decrypt (Box. pbk pvk) nonce ciphertext)))
