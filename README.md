# caesium

caesium is a Clojure binding to the Networking and Cryptography (NaCl) library.

It aims to provide an idiomatic Clojure API on top of
[kalium](https://github.com/abstractj/kalium), the Java binding to
[Networking and Cryptography](http://nacl.cr.yp.to/) library by
[Daniel J. Bernstein](http://cr.yp.to/djb.html). In turn, kalium builds on
cool software like [libsodium](https://github.com/jedisct1/libsodium) and
[RbNaCl](https://github.com/cryptosphere/rbnacl).

"Real" development should most likely happen in the parent library, so that
this one can stay a simple bunch of wrappers.

## License

Copyright © 2014 the caesium authors (see AUTHORS)

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
