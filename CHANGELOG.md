# 0.5.0

Pretty much a rewrite. Now binds libsodium directly with jnr-ffi instead of
using `kalium`.

* lots of extra APIs exposed; check the API docs :-)
* `sha256`, `sha512` were moved from `crypto.generichash` to `crypto.hash`
  to match libsodium.
* `blake2b` hashes were previously 64 bytes by default because that is the
  default in kalium (see abstractj/kalium#54), although the blake2b spec says
  they're 32 bytes by default, which is also what libsodium does. caesium now
  defaults to the libsodium behavior.
* The `crypto_box` key generation API from kalium, when given a secret input
  to produce a key pair, would manually do the curve scalar mult. This is not
  what libsodium does when producing a key pair from a secret: libsodium
  hashes the input first. caesium exposes the libsodium API by default (part
  of the general rule of "be like libsodium"), and has a new fn,
  `sk->keypair`, to reproduce the old behavior.
* As a consequence of the above point, caesium now exposes scalarmult, so you
  can perform scalar multiplication against a given point or against the base
  point. You probably don't want to use that API directly.
* `secretbox/int->nonce` now returns an entirely big-endian array; instead of
  a big-endian number that's padded at the end (potentially confusingly
  returning `0x01 0x00 ...`, which doesn't look like it has the MSB at the
  end). This breaks backwards compatibility within caesium, but improves
  compatibility with other systems.
* init moved from `caesium.core` to `caesium.sodium` for consistency

# 0.4.0

@cbowdon added a bunch of features:

- `crypto.box`, asymmetric encryption primitives
- `crypto.sign`, asymmetric signatures
- `generichash` now has SHA-256, SHA-512 bindings

Added better linting tools to CI.

# 0.3.0

Type hinting, resulting in performance gains:

- `randombytes` knows it's calling `Random`
- `array-eq` knows it's working with byte arrays. (This might be a
  regression if you were using it to compare non-byte arrays.)

`*warn-on-reflection*` has been turned on to prevent future hinting
issues.

`caesium.crypto.util` has been renamed to `crypto.util`, because it
broke the "follow libsodium" rule. Furthermore, there is nothing
cryptographic about that module. (I'm not terribly happy about doing
this, even though it's 0.x. Nonetheless, it's a band-aid that needed
to be ripped off.)

# 0.2.0

Added support for:

- randombytes (caesium.randombytes)
- sodium_init (caesium.core.sodium-init)

# 0.1.2

As 0.1.1, but actually supporting those features, by bumping the
kalium dependency to 0.3.0.

# 0.1.1

This release will never be uploaded anywhere because the upstream
dependency, kalium, does not yet have a release that supports all
features caesium exposes.

- generichash (BLAKE2b) support
- secretbox (XSalsa20 + Poly1305-AES) support
