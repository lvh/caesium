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
  limited use.")

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

  To decrypt, use [[decrypt]] or [[open]], depending on which argument order
  you prefer."
  [msg nonce key])

(defn secretbox-rnd
  "secretbox, with randomized prefix nonce.

  This is useful if you don't have an obvious nonce in your protocol
  you can use. However, it does rely on having a cryptographically
  secure CSPRNG available during encryption. It is *not* nonce-misuse
  resistant. Unless you can't afford the minor performance penalty for
  a nonce-misuse resistant scheme, consider using [[secretbox-nmr]].

  To decrypt, use [[decrypt]] or [[open]], depending on which argument
  order you prefer."
  [msg key])

(defn ^:private synthetic-nonce
  "Creates a synthetic nonce from the given plaintext.

  This function is pure in the sense that it is deterministic and has
  no visible side effects: the same plaintext will always generate the
  same byte array. However, note that the returned nonce will be a
  mutable byte array."
  [plaintext])

(defn ^:private random-nonce!
  "Creates a random nonce suitable for use in secretbox.

  This function is not pure: it will request a different random nonce from
  the CSPRNG every time."
  [])

(defn ^:private xor!
  "Populates `out` with the XOR of matching elements in `a`, `b`.

  All three arrays should be of identical length. Returns `out`."
  [^bytes out ^bytes a ^bytes b]
  (dotimes [i (alength a)]
    (aset-byte out i (bit-xor (aget a i) (aget b i))))
  out)

(defn ^:private xor-inplace!
  "XORs elements of array `a` in-place with the matching elem from `b`."
  [^bytes a ^bytes b]
  (xor! a a b))

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

  To decrypt, use [[decrypt]] or [[open]], depending on which argument order
  you prefer."
  [msg key])

(defn secretbox-nmr
  "Encrypt a message like secretbox, but nonce-misuse resistant.

  This still optionally takes a nonce, but that nonce will be combined
  with a synthetic nonce. This means that if the nonce incidentally
  repeats, an attacker will only be able to tell that a message
  repeated, instead of the usual plaintext disclosure that happens.

  If no nonce argument is specified, a random nonce is automatically
  selected for you, and the NMR scheme is applied on top of that."
  ([msg nonce key])
  ([msg key]
   (secretbox-nmr msg (random-nonce!) key)))

(defn decrypt-to-buf!
  "Decrypts any secretbox message with a prefix nonce into the given buffer."
  [out key ctext])

(defn decrypt
  "Decrypts any secretbox message with a prefix nonce."
  [key ctext])

(defn open-to-buf!
  "Open (decrypt and verify) a nonce-prefixed secretbox message."
  [out ctext key])

(defn open
  "Like [[decrypt]], but with different argument order; analogous to
  [[caesium.crypto.secretbox/secretbox-open-easy]]."
  [ctext key])
