(ns caesium.magicnonce.secretbox
  "\"Magic\" nonce schemes for secretbox.

  There are two kinds of schemes in this namespace:

   * schemes that take a nonce, but do something with it to make the
     resulting system safer or easier to use,
   * schemes that produce the nonce for you automatically.

  See individual function docstrings for details, but the most
  interesting function in this namespace is [[secretbox-nmr]]. If you
  just want a random nonce and do not care about nonce-misuse
  resistance, use [[secretbox-rnd]]. The other functions are fairly
  limited use."
  (:require [caesium.crypto.generichash :as g]
            [caesium.crypto.secretbox :as s]
            [caesium.randombytes :as r]
            [caesium.byte-bufs :as bb])
  (:import (java.nio ByteBuffer)))

(def keybytes s/keybytes)

(defn secretbox-pfx
  "secretbox, with the given nonce embedded in the ciphertext as a prefix.

  This is only useful if there is an obvious nonce in your protocol
  that can not repeat, you have ways of detecting when your peer
  epeats nonces, your nonce is not implicitly part of your protocol so
  you have to specify it as part of the ciphertext, and you can not
  afford to use a nonce-misuse resistant scheme. As you can see,
  that's a fairly rare circumstance; this function is mainly used
  internally by other, easier to use schemes in this namespace. Check
  out [[secretbox-nmr]] instead.

  The resulting layout will be 24 bytes of nonce, followed by the
  secretbox ciphertext (which itself consists of the encryption of the
  plaintext, followed by a 16 byte MAC).

  To decrypt, use [[decrypt]] or [[open]], depending on which argument order
  you prefer."
  [m n k]
  (let [mlen (bb/buflen m)
        clen (+ s/macbytes mlen)
        outlen (+ s/noncebytes clen)
        out (byte-array outlen)
        cbuf (ByteBuffer/wrap out s/noncebytes clen)]
    (System/arraycopy n 0 out 0 s/noncebytes)
    (s/secretbox-easy-to-buf! cbuf m n k)
    out))

(defn ^:private random-nonce!
  "Creates a random nonce suitable for use in secretbox.

  This function is not pure: it will request a different random nonce from
  the CSPRNG every time."
  []
  (r/randombytes s/noncebytes))

(defn secretbox-rnd
  "secretbox, with randomized prefix nonce.

  This is useful if you don't have an obvious nonce in your protocol
  you can use. However, it does rely on having cryptographically
  strong randomness available during encryption. It is *not*
  nonce-misuse resistant. Unless you can't afford the minor
  performance penalty for a nonce-misuse resistant scheme, consider
  using [[secretbox-nmr]].

  To decrypt, use [[decrypt]] or [[open]], depending on which argument
  order you prefer."
  [msg key]
  (secretbox-pfx msg (random-nonce!) key))

(def ^:private synthetic-personal
  "The BLAKE2b personal used for synthetic nonce generation.

  This says sodium, not caesium, in a vain hope that this ciphersuite gets
  picked up by other libsodium bindings."
  (.getBytes "sodium autononce"))

(defn ^:private synthetic-nonce
  "Creates a synthetic nonce from the given plaintext.

  This function is pure in the sense that it is deterministic and has
  no visible side effects: the same plaintext will always generate the
  same byte array. However, note that the returned nonce will be a
  mutable byte array."
  [plaintext key]
  (g/blake2b plaintext {:size s/noncebytes
                        :key key
                        :personal synthetic-personal}))

(defn secretbox-det
  "secretbox, with deterministic nonce.

  This means the encryption operation requires no new randomness; it
  is a fully deterministic cryptosystem. This means identical
  plaintexts will map to identical ciphertexts. That has to be
  acceptable for your protocol!

  Because the nonce is determined from the plaintext, adding any
  non-determinism to your message will make the nonce not repeat and
  hence hide repeated messages from the attacker. A high-resolution
  timestamp will do that effectively in most cases.

  This scheme does not change the requirements for the key: the key
  must still be a cryptographically random byte array of appropriate
  size ([[caesium.crypto.secretbox/keybytes]]).

  Unless you know for sure that repeat messages are OK or that your
  messages will not repeat or you can't rely on encryption-time
  randomness, consider [[secrebox-nmr]].

  To decrypt, use [[decrypt]] or [[open]], depending on which argument
  order you prefer."
  [msg key]
  (secretbox-pfx msg (synthetic-nonce msg key) key))

(defn ^:private xor!
  "Populates `out` with the XOR of matching elements in `a`, `b`.

  All three arrays should be of identical length. Returns `out`."
  [^bytes out ^bytes a ^bytes b]
  (dotimes [i (bb/buflen a)]
    (aset-byte out i (bit-xor (aget a i) (aget b i))))
  out)

(defn ^:private xor-inplace!
  "XORs elements of array `a` in-place with the matching elem from `b`."
  [^bytes a ^bytes b]
  (xor! a a b))

(defn secretbox-nmr
  "Encrypt a message like secretbox, but nonce-misuse resistant.

  This still optionally takes a nonce, but that nonce will be combined
  with a synthetic nonce. This means that if the nonce incidentally
  repeats, an attacker will only be able to tell that a message
  repeated, instead of the usual plaintext disclosure that happens.

  If no nonce argument is specified, a random nonce is automatically
  selected for you, and the NMR scheme is applied on top of that."
  ([msg nonce key]
   (secretbox-pfx msg (xor-inplace! (synthetic-nonce msg key) nonce) key))
  ([msg key]
   (secretbox-nmr msg (random-nonce!) key)))

(defn open-to-buf!
  "Decrypts any secretbox message with a prefix nonce into the given buffer.

  Analogous to [[caesium.crypto.secretbox/secretbox-open-easy-to-buf!]]."
  [^bytes out ^bytes nonced-ctext ^bytes key]
  (let [noncebuf (ByteBuffer/wrap nonced-ctext 0 s/noncebytes)
        ctextlen (- (buflen nonced-ctext) s/noncebytes)
        ctextbuf (ByteBuffer/wrap nonced-ctext s/noncebytes ctextlen)]
    (s/secretbox-open-easy-from-byte-bufs! out ctextbuf ctextlen noncebuf key)))

(defn open
  "Decrypts any secretbox message with a prefix nonce.

  Analogous to [[caesium.crypto.secretbox/secretbox-open-easy]]."
  [^bytes nonced-ctext ^bytes key]
  (let [out (byte-array (- (buflen nonced-ctext) s/noncebytes s/macbytes))]
    (open-to-buf! out nonced-ctext key)))

(defn decrypt-to-buf!
  "Like [[open-to-buf!]], but with different argument order."
  [out key nonced-ctext]
  (open-to-buf! out nonced-ctext key))

(defn decrypt
  "Like [[open]], but with different argument order."
  [key nonced-ctext]
  (open nonced-ctext key))
