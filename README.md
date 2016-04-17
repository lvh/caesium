# caesium

![caesium spectral lines](https://dl.dropboxusercontent.com/u/38476311/Logos/caesium.png)

[![Build Status](https://travis-ci.org/lvh/caesium.svg?branch=master)](https://travis-ci.org/lvh/caesium)

[![Clojars Project](http://clojars.org/caesium/latest-version.svg)](http://clojars.org/caesium)

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
[documentation for libsodium][libsodiumdocs]. Since it's all just tiny
wrappers around that, everything in it applies.

[libsodiumdocs]: http://doc.libsodium.org

## Differences with other bindings

caesium tries to just give you the libsodium experience from Clojure. It maps
fns to predictable names; `sodium_crypto_secretbox_open_easy` will be called
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
* functions designed to make a `#define` constant available are accessible as
  values, they don't need to be called. For example, you can access the
  `crypto_generichash_KEYBYTES_MIN` constant via the `libsodium` `size_t
  crypto_generichash_keybytes_min(void);` function, but in caesium, it's just
  `caesium.crypto.generichash/keybytes-min` (not a function you have to call).

All APIs take `byte[]`, never `String`, for maximum similarity with
`libsodium`. `caesium` doesn't hide the no-magic C APIs from you; but you have
to understand libsodium to use them. The upside of that is that this library
provides the APIs necessary to use `libsodium` safely; e.g. with locked
buffers with canaries, secure memset, et cetera.

## Compatibility

caesium uses [semver](http://semver.org/).

Since this is a security-sensitive library, I will actively remove functions
or APIs that have serious security problems, instead of simply documenting the
problem.

## License

Copyright © the caesium authors (see AUTHORS)

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
