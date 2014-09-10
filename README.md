# caesium

![caesium spectral lines](https://dl.dropboxusercontent.com/u/38476311/Logos/caesium.png)

caesium is a Clojure binding for libsodium.

It builds on top of [kalium][kalium], the Java binding to
[libsodium][libsodium], which in turn is a more convenient fork of
the original [NaCl][nacl] library by [djb][djb].

[kalium]: https://github.com/abstractj/kalium
[nacl]: http://nacl.cr.yp.to/.
[djb]: http://cr.yp.to/djb.html
[libsodium]: https://github.com/jedisct1/libsodium

## Differences between kalium and caesium

Despite caesium being a thin wrapper around kalium, there are some
differences, mostly in the interest of being more Clojure-friendly.

"Real" development should most likely happen in the parent library, so
that this one can stay a simple bunch of wrappers. However, this is
just a generic rule, and convenience trumps it.

Unlike kalium, caesium just exposes functions instead of instantiating
objects. (It instantiates objects internally, but ideally you never
see them.)

Unlike kalium, caesium follows the structure of libsodium. For
example, in libsodium, BLAKE2b lives in `crypto_generichash`. In
kalium, it lives in the `org.kalium.crypto.Hash` class. In caesium, it
lives in the `caesium.crypto.generichash` namespace.

Unlike kalium, encoders (hex, base64...) are decomplected from APIs.
All APIs take `byte[]`, never `String`. While the API kalium uses
makes sense when you're consuming it from Java, it's much simpler to
just have function calls in Clojure.

## License

Copyright © 2014 the caesium authors (see AUTHORS)

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
