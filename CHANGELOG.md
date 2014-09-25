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
