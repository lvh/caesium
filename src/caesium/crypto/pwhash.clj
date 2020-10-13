(ns caesium.crypto.pwhash
  (:refer-clojure :exclude [bytes hash])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]
            [caesium.util :as u]
            [medley.core :as m]))

(declare alg-argon2i13
         alg-argon2id13
         alg-default
         bytes-min
         bytes-max
         passwd-min
         passwd-max
         saltbytes
         strbytes
         strprefix
         opslimit-min
         opslimit-max
         memlimit-min
         memlimit-max
         opslimit-interactive
         memlimit-interactive
         opslimit-moderate
         memlimit-moderate
         opslimit-sensitive
         memlimit-sensitive
         primitive

         argon2i-alg-argon2i13
         argon2i-bytes-min
         argon2i-bytes-max
         argon2i-passwd-min
         argon2i-passwd-max
         argon2i-saltbytes
         argon2i-strbytes
         argon2i-strprefix
         argon2i-opslimit-min
         argon2i-opslimit-max
         argon2i-memlimit-min
         argon2i-memlimit-max
         argon2i-opslimit-interactive
         argon2i-memlimit-interactive
         argon2i-opslimit-moderate
         argon2i-memlimit-moderate
         argon2i-opslimit-sensitive
         argon2i-memlimit-sensitive

         argon2id-alg-argon2id13
         argon2id-bytes-min
         argon2id-bytes-max
         argon2id-passwd-min
         argon2id-passwd-max
         argon2id-saltbytes
         argon2id-strbytes
         argon2id-strprefix
         argon2id-opslimit-min
         argon2id-opslimit-max
         argon2id-memlimit-min
         argon2id-memlimit-max
         argon2id-opslimit-interactive
         argon2id-memlimit-interactive
         argon2id-opslimit-moderate
         argon2id-memlimit-moderate
         argon2id-opslimit-sensitive
         argon2id-memlimit-sensitive

         scryptsalsa208sha256-bytes-min
         scryptsalsa208sha256-bytes-max
         scryptsalsa208sha256-passwd-min
         scryptsalsa208sha256-passwd-max
         scryptsalsa208sha256-saltbytes
         scryptsalsa208sha256-strbytes
         scryptsalsa208sha256-strprefix
         scryptsalsa208sha256-opslimit-min
         scryptsalsa208sha256-opslimit-max
         scryptsalsa208sha256-memlimit-min
         scryptsalsa208sha256-memlimit-max
         scryptsalsa208sha256-opslimit-interactive
         scryptsalsa208sha256-memlimit-interactive
         scryptsalsa208sha256-opslimit-sensitive
         scryptsalsa208sha256-memlimit-sensitive)

(b/defconsts [alg-argon2i13
              alg-argon2id13
              alg-default
              bytes-min
              bytes-max
              passwd-min
              passwd-max
              saltbytes
              strbytes
              strprefix
              opslimit-min
              opslimit-max
              memlimit-min
              memlimit-max
              opslimit-interactive
              memlimit-interactive
              opslimit-moderate
              memlimit-moderate
              opslimit-sensitive
              memlimit-sensitive
              primitive

              argon2i-alg-argon2i13
              argon2i-bytes-min
              argon2i-bytes-max
              argon2i-passwd-min
              argon2i-passwd-max
              argon2i-saltbytes
              argon2i-strbytes
              argon2i-strprefix
              argon2i-opslimit-min
              argon2i-opslimit-max
              argon2i-memlimit-min
              argon2i-memlimit-max
              argon2i-opslimit-interactive
              argon2i-memlimit-interactive
              argon2i-opslimit-moderate
              argon2i-memlimit-moderate
              argon2i-opslimit-sensitive
              argon2i-memlimit-sensitive

              argon2id-alg-argon2id13
              argon2id-bytes-min
              argon2id-bytes-max
              argon2id-passwd-min
              argon2id-passwd-max
              argon2id-saltbytes
              argon2id-strbytes
              argon2id-strprefix
              argon2id-opslimit-min
              argon2id-opslimit-max
              argon2id-memlimit-min
              argon2id-memlimit-max
              argon2id-opslimit-interactive
              argon2id-memlimit-interactive
              argon2id-opslimit-moderate
              argon2id-memlimit-moderate
              argon2id-opslimit-sensitive
              argon2id-memlimit-sensitive

              scryptsalsa208sha256-bytes-min
              scryptsalsa208sha256-bytes-max
              scryptsalsa208sha256-passwd-min
              scryptsalsa208sha256-passwd-max
              scryptsalsa208sha256-saltbytes
              scryptsalsa208sha256-strbytes
              scryptsalsa208sha256-strprefix
              scryptsalsa208sha256-opslimit-min
              scryptsalsa208sha256-opslimit-max
              scryptsalsa208sha256-memlimit-min
              scryptsalsa208sha256-memlimit-max
              scryptsalsa208sha256-opslimit-interactive
              scryptsalsa208sha256-memlimit-interactive
              scryptsalsa208sha256-opslimit-sensitive
              scryptsalsa208sha256-memlimit-sensitive])

(defn pwhash-to-buf!
  [buf msg salt opslimit memlimit alg]
  (b/call! pwhash buf msg salt opslimit memlimit alg)
  buf)

(defn pwhash
  "hashes a given password using default method"
  [key-size msg salt opslimit memlimit alg]
  (let [buf (bb/alloc key-size)]
    (pwhash-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     (bb/->indirect-byte-buf salt)
     opslimit memlimit alg)
    (bb/->bytes buf)))

(defn pwhash-str-to-buf!
  [buf msg opslimit memlimit]
  (b/call! pwhash-str buf msg opslimit memlimit)
  buf)

(defn pwhash-str
  "returns a string hash complete with all information required to verify"
  [msg opslimit memlimit]
  (let [buf (bb/alloc strbytes)]
    (pwhash-str-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     opslimit memlimit)
    (String. (bb/->bytes buf))))

(defn pwhash-str-alg-to-buf!
  [buf msg opslimit memlimit alg]
  (b/call! pwhash-str-alg buf msg opslimit memlimit alg)
  buf)

(defn pwhash-str-alg
  [msg opslimit memlimit alg]
  (let [buf (bb/alloc strbytes)]
    (pwhash-str-alg-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     opslimit memlimit alg)
    (String. (bb/->bytes buf))))

(defn pwhash-str-verify
  [hashpass passwd]
  (let [buf (bb/->indirect-byte-buf hashpass)
        msg (bb/->indirect-byte-buf passwd)]
    (b/call! pwhash-str-verify buf msg)))

(defn str-needs-rehash
  [hashpass opslimit memlimit]
  (let [buf (bb/->indirect-byte-buf hashpass)]
    (b/call! str-needs-rehash buf opslimit memlimit)))

(defn pwhash-argon2i-to-buf!
  [buf msg salt opslimit memlimit alg]
  (b/call! pwhash-argon2i buf msg salt opslimit memlimit alg)
  buf)

(defn argon2i-str-to-buf!
  [buf msg opslimit memlimit]
  (b/call! pwhash-argon2i-str buf msg opslimit memlimit)
  buf)

(defn argon2i
  "hashes a given password using argon2i"
  [key-size msg salt opslimit memlimit alg]
  (let [buf (bb/alloc key-size)]
    (pwhash-argon2i-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     (bb/->indirect-byte-buf salt)
     opslimit memlimit alg)
    (bb/->bytes buf)))

(defn argon2i-str
  [msg opslimit memlimit]
  (let [buf (bb/alloc strbytes)]
    (argon2i-str-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     opslimit memlimit)
    (String. (bb/->bytes buf))))

(defn argon2i-str-verify
  [hashpass passwd]
  (let [buf (bb/->indirect-byte-buf hashpass)
        msg (bb/->indirect-byte-buf passwd)]
    (b/call! argon2i-str-verify buf msg)))

(defn argon2i-str-needs-rehash
  [hashpass opslimit memlimit]
  (let [buf (bb/->indirect-byte-buf hashpass)]
    (b/call! argon2i-str-needs-rehash buf opslimit memlimit)))

(defn argon2id-to-buf!
  [buf msg salt opslimit memlimit alg]
  (b/call! pwhash-argon2id buf msg salt opslimit memlimit alg)
  buf)

(defn argon2id
  "hashes a given password using argon2id"
  [key-size msg salt opslimit memlimit alg]
  (let [buf (bb/alloc key-size)]
    (argon2id-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     (bb/->indirect-byte-buf salt)
     opslimit memlimit alg)
    (bb/->bytes buf)))

(defn argon2id-str-to-buf!
  [buf msg opslimit memlimit]
  (b/call! pwhash-argon2id-str buf msg opslimit memlimit)
  buf)

(defn argon2id-str
  [msg opslimit memlimit]
  (let [buf (bb/alloc strbytes)]
    (argon2id-str-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     opslimit memlimit)
    (String. (bb/->bytes buf))))

(defn argon2id-str-verify
  [hashpass passwd]
  (let [buf (bb/->indirect-byte-buf hashpass)
        msg (bb/->indirect-byte-buf passwd)]
    (b/call! argon2id-str-verify buf msg)))

(defn argon2id-str-needs-rehash
  [hashpass opslimit memlimit]
  (let [buf (bb/->indirect-byte-buf hashpass)]
    (b/call! argon2id-str-needs-rehash buf opslimit memlimit)))

(defn scryptsalsa208sha256-to-buf!
  [buf msg salt opslimit memlimit]
  (b/call! pwhash-scryptsalsa208sha256 buf msg salt opslimit memlimit)
  buf)

(defn scryptsalsa208sha256
  "hashes a given password using scryptsalsa208sha256"
  [key-size msg salt opslimit memlimit]
  (let [buf (bb/alloc key-size)]
    (scryptsalsa208sha256-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     (bb/->indirect-byte-buf salt)
     opslimit memlimit)
    (bb/->bytes buf)))

(defn scryptsalsa208sha256-str-to-buf!
  [buf msg opslimit memlimit]
  (b/call! pwhash-scryptsalsa208sha256-str buf msg opslimit memlimit)
  buf)

(defn scryptsalsa208sha256-str
  [msg opslimit memlimit]
  (let [buf (bb/alloc strbytes)]
    (scryptsalsa208sha256-str-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     opslimit memlimit)
    (String. (bb/->bytes buf))))

(defn scryptsalsa208sha256-str-verify
  [hashpass passwd]
  (let [buf (bb/->indirect-byte-buf hashpass)
        msg (bb/->indirect-byte-buf passwd)]
    (b/call! scryptsalsa208sha256-str-verify buf msg)))

(defn scryptsalsa208sha256-str-needs-rehash
  [hashpass opslimit memlimit]
  (let [buf (bb/->indirect-byte-buf hashpass)]
    (b/call!  scryptsalsa208sha256-str-needs-rehash buf opslimit memlimit)))
