# 0.8.0 (WIP)

Standardized and improved way APIs deal with the different byte APIs exposed
by the JVM. In short: convenience fns (which manage buffers for you) always
return byte arrays and consume any type that can be converted to a sequence of
bytes; low-level `*-to-buf!` fns now take `ByteBuffer`, never byte
arrays. Only the latter is a breaking change. See the following blog post for
full rationale and details:
https://www.lvh.io/posts/crypto-apis-and-jvm-byte-types.html

As a part of this change, `random-to-byte-array!` is gone, and
`random-to-byte-buffer!` has been renamed to `random-to-buf!` for consistency
with other APIs. `secretbox-open-easy-from-byte-bufs!` is similarly gone. All
of these removed APIs were marked as being for highly specialized use, so if
you were already using them successfully you can probably use the new API
pretty painlessly (if not, please file an issue).

The argument order for signing functions was inconsistent with libsodium and
therefore also other APIs in caesium. This has been changed. The signature for
`scalarmult-to-buf!` was inconsistent with other signatures; this has been
changed. In the same namespace, `int->scalar` fn has been moved to the test
namespace since it was a security footgun (this was already documented in the
docstring, but there is really no good reason to use it, so it's simply been
removed from the scalarmult namespace instead).

caesium.crypto.sign/generate-keypair is deprecated in favor of keypair! in the
same ns for consistency with libsodium (and caesium.crypto.box). (#7)

Removed the kalium dependency. This might be a breaking change if your project
used kalium directly and counted on caesium to pull it in for you; kalium has
not been used since before 0.6.0.

# 0.7.0

Pseudo-availability of magic nonce schemes -- use at your own risk!

# 0.6.0

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

# 0.5.0

Accidentally botched release; see 0.6.0. Tagged, but not signed or artifacts
pushed.

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
