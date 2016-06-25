# caesium

![caesium spectral lines](https://dl.dropboxusercontent.com/u/38476311/Logos/caesium.png)

[![Clojars Project](http://clojars.org/caesium/latest-version.svg)](http://clojars.org/caesium)
[![Build Status](https://travis-ci.org/lvh/caesium.svg?branch=master)](https://travis-ci.org/lvh/caesium)
[![codecov](https://codecov.io/gh/lvh/caesium/branch/master/graph/badge.svg)](https://codecov.io/gh/lvh/caesium)

caesium is a Clojure binding for libsodium.

It is a direct [jnr-ffi][jnr-ffi] binding to [libsodium][libsodium], which in
turn is a more convenient fork of the original [NaCl][nacl] library by
[djb][djb].

[jnr-ffi]: https://github.com/jnr/jnr-ffi
[nacl]: http://nacl.cr.yp.to/.
[djb]: http://cr.yp.to/djb.html
[libsodium]: https://github.com/jedisct1/libsodium

## Documentation

The most important documentation for caesium is actually the
[documentation for libsodium][libsodiumdocs]. Since it's all just relatively
small wrappers around that, everything in it applies.

[libsodiumdocs]: http://doc.libsodium.org

## Differences with other bindings

Instead of making specific claims about specific libraries which may become
outdated, here are a few properties you may care about:

* caesium is written by a cryptographer who has experience binding
  cryptographic libraries.
* caesium has continuous integration and a fairly extensive test suite with
  very high form/line coverage.
* caesium does not provide magic layers on top of libsodium that prevent you
  from writing secure software because of JVM memory semantics, while not
  getting in your way if you want the default good-enough behavior.
* caesium uses jnr-ffi pinning correctly; resulting in zero-copy behavior
  between JVM and C land at the call site.
* All APIs take `byte[]` and in some cases `ByteBuffer`, never `String`. This
  gives you the option of zeroing byte arrays out once you're done. `caesium`
  doesn't hide the no-magic C APIs from you; but you have to understand
  libsodium to use them. The upside of that is that this library provides the
  APIs necessary to use `libsodium` safely; e.g. with locked buffers with
  canaries, secure memset, et cetera.
* caesium's APIs match libsodium's behavior. If libsodium hashes a seed to
  produce a keypair, caesium will hash a seed to produce a keypair. If
  libsodium uses the default output size of a particular hash function,
  caesium will use the default output size of that hash function. (These were
  at time of writing not true for at least 1 other library).

caesium tries to just give you the libsodium experience from Clojure. C
pseudo-namespaces are mapped to real Cojure namespaces. It usually maps fns to
predictable names; `sodium_crypto_secretbox_open_easy` will be called
`caesium.crypto.secretbox/open-easy`. Formally: take the C pseudo-namespace,
turn it into a real namespace, replace the leading `sodium` with caesium,
replace underscores with dashes. Exceptions where this doesn't work out:

* sometimes, the last part of the C pseudo-namespace is repeated. This happens
  for functions that have the same name as a C pseudo-namespace,
  e.g. `crypto_generichash` (which is also the pseudo-namespace for
  e.g. `crypto_generichash_init`). These would be available in the
  `caesium.crypto.generichash` namespace, as `generichash` and `init`. This is
  also repeated for some functions where there is a small suffix, e.g. the
  function name for the "easy secretbox opener" is `secretbox-easy-open`, not
  `easy-open`.
* some functions map to the same underlying C functions, but have different
  Java APIs. For example, one of them might cast to `ByteBuffer`, while others
  assume byte arrays, while others rely on reflection to call the right
  thing. Other pairs of functions might expect you to produce the output
  buffer, or manage the output buffer for you. Since these are only JVM-level
  differences, these often need different names at the JVM/Clojure
  level. (This is always done as a fairly descriptive suffix.)
* functions designed to make a `#define` constant available are accessible as
  values, they don't need to be called. For example, you can access the
  `crypto_generichash_KEYBYTES_MIN` constant via the `libsodium` `size_t
  crypto_generichash_keybytes_min(void);` function, but in caesium, it's just
  `caesium.crypto.generichash/keybytes-min` (not a function you have to call).
* some families of functions in libsodium are a consequence of C not
  supporting multi-arity functions; e.g. `scalarmult` in libsodium has two
  functions: one with the fixed base point and one with an explicit base
  point; caesium just has one function with two arities.
* caesium sometimes takes a little artistic license with some of the exposed
  names when that makes more sense than the original; generally fns will be
  available under both the "official" name and an alias.

## Compatibility

caesium uses [semver](http://semver.org/).

Since this is a security-sensitive library, I will actively remove functions
or APIs that have serious security problems, instead of simply documenting the
problem.

## License

Copyright © the caesium authors (see AUTHORS)

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
