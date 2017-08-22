(ns caesium.crypto.pwhash
  (:refer-clojure :exclude [bytes hash])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]
            [caesium.util :as u]
            [medley.core :as m]))

(b/defconsts [alg-argon2i13
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
              argon2i-memlimit-sensitive])


(defn pwhash-to-buf!
  [buf msg salt opslimit memlimit alg]
  (b/✨ pwhash buf msg salt opslimit memlimit alg)
  buf)

(defn pwhash-argon2i-to-buf!
  [buf msg salt opslimit memlimit alg]
  (b/✨ pwhash-argon2i buf msg salt opslimit memlimit alg)
  buf)

(defn pwhash-str-to-buf!
  [buf msg opslimit memlimit]
  (b/✨ pwhash-str buf msg opslimit memlimit)
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

(defn pwhash-argon2i
  "hashes a given password using argon2i"
  [key-size msg salt opslimit memlimit alg]
   (let [buf (bb/alloc key-size)]
     (pwhash-argon2i-to-buf!
      buf 
      (bb/->indirect-byte-buf msg)
      (bb/->indirect-byte-buf salt)
      opslimit memlimit alg)
     (bb/->bytes buf)))

(defn pwhash-str
  [msg opslimit memlimit]
  (let [buf (bb/alloc strbytes)]
    (pwhash-str-to-buf!
     buf
     (bb/->indirect-byte-buf msg)
     opslimit memlimit)
     (String. (bb/->bytes buf))))

(defn pwhash-str-verify
  [hashpass msg]
  (let [buf (bb/->bytes hashpass)]
    (b/✨ pwhash-str-verify
    (bb/->indirect-byte-buf buf)
    (bb/->indirect-byte-buf msg))))
  
  
              

