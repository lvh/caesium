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
replace underscores with dashes. One exception: `libsodium` has functions at
the `sodium` top level, e.g. `sodium_init`, `sodium_memcmp`, et cetera. These
can be accessed at `caesium.core/init`.

All APIs take `byte[]`, never `String`, for maximum similarity with
`libsodium`. `caesium` does no magic for you; you're expected to understand
`libsodium` in order to use this library. The upside of that is that this
library provides the APIs necessary to use `libsodium` safely; e.g. with
locked buffers with canaries, secure memset, et cetera.

## Compatibility

caesium uses [semver](http://semver.org/).

I will try not to break backwards compatibility unnecessarily, even in
major versions. However, since this is a security-sensitive library, I
will actively remove functions or APIs that have serious security
problems, instead of simply documenting the problem. Hence, despite
the rapidly changing major version numbers, you are strongly
encouraged to always upgrade to the latest version. If it breaks your
code, that's a sign your code might have a previously undetected
issue.

## License

Copyright © the caesium authors (see AUTHORS)

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
