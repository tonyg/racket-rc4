#lang racket/base
;; Copyright (c) 2011 Tony Garnock-Jones <tonygarnockjones@gmail.com>
;;
;; Permission is hereby granted, free of charge, to any person
;; obtaining a copy of this software and associated documentation
;; files (the "Software"), to deal in the Software without
;; restriction, including without limitation the rights to use, copy,
;; modify, merge, publish, distribute, sublicense, and/or sell copies
;; of the Software, and to permit persons to whom the Software is
;; furnished to do so, subject to the following conditions:
;;
;; The above copyright notice and this permission notice shall be
;; included in all copies or substantial portions of the Software.
;;
;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
;; EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
;; MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
;; NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
;; HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
;; WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
;; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
;; DEALINGS IN THE SOFTWARE.

(require racket/generator)
(require racket/sequence)

(provide sequence->bytes
	 sequence->bytes/length
	 rc4-initialize
	 rc4-stream-generator
	 in-rc4-stream*
	 in-rc4-stream
	 xor-generator
	 in-xor
	 in-rc4)

;; An RC4State is a Vector of length 256 containing bytes. It
;; represents the internal state of the stream cipher.

;; sequence? -> bytes?
;; Converts the entirety of its argument into a byte-vector.
;; Expects each element of seq to be a byte.
(define (sequence->bytes seq)
  (list->bytes (sequence->list seq)))

;; exact-integer? sequence? -> bytes?
;; Returns a byte-vector of length `length`. The first `length` bytes
;; from `seq` (or the entirety of `seq`, if it contains fewer than
;; `length` elements) are placed in the leading bytes of the result.
(define (sequence->bytes/length length seq)
  (define result (make-bytes length))
  (for ([(i b) (in-parallel length seq)])
    (bytes-set! result i b))
  result)

;; vector? exact-integer? exact-integer? -> void?
;; Exchanges elements i and j of vector S.
(define (swap! S i j)
  (define Sj (vector-ref S j))
  (vector-set! S j (vector-ref S i))
  (vector-set! S i Sj))

;; bytes? [exact-integer?] -> RC4State
;; Initialise stream cipher state from the given key bytes.
;; The repeat-count is to accommodate CipherSaber-2.
(define (rc4-initialize key [repeat-count 1])
  (define keylength (bytes-length key))
  (define S (for/vector ([i 256]) i))
  (define j 0)
  (for ([_ repeat-count])
    (for ([i 256])
      (set! j (bitwise-and 255 (+ j (vector-ref S i) (bytes-ref key (modulo i keylength)))))
      (swap! S i j)))
  S)

;; RC4State exact-integer? -> ( -> byte? )
;; Produces a stateful generator procedure which, when called, returns
;; the next byte in the RC4 stream. Before returning the procedure,
;; calls it `drop-count` times, to discard the first `drop-count`
;; bytes of stream output. RC4 is a weak cipher when called with
;; values for `drop-count` less than 768; a conservative value for
;; `drop-count` is 3072. See
;; http://www.users.zetnet.co.uk/hopwood/crypto/scan/cs.html#RC4-drop.
(define (rc4-stream-generator S drop-count)
  (define i 0)
  (define j 0)
  (define (round)
    (set! i (bitwise-and 255 (+ i 1)))
    (set! j (bitwise-and 255 (+ j (vector-ref S i))))
    (swap! S i j)
    (vector-ref S (bitwise-and 255 (+ (vector-ref S i) (vector-ref S j)))))
  (for ([_ drop-count]) (round))
  round)

;; RC4State exact-integer? -> sequence?
;; As per `rc4-stream-generator`, but returns a sequence suitable for
;; use with `for` etc.
(define (in-rc4-stream* S drop-count) (in-producer (rc4-stream-generator S drop-count) #f))

;; bytes? exact-integer? -> sequence?
;; As per `in-rc4-stream*`, but constructs the initial RC4State for
;; you, using the key provided.
(define (in-rc4-stream key drop-count) (in-rc4-stream* (rc4-initialize key) drop-count))

;; sequence? sequence? -> ( -> exact-integer? )
;; Returns a stateful generator procedure which XORs together pairs of
;; numbers from `seq1` and `seq2`. Useful for combining stream-cipher
;; output with plain- or ciphertext, for example.
(define (xor-generator seq1 seq2)
  (generator ()
    (for ([(b1 b2) (in-parallel seq1 seq2)])
      (yield (bitwise-xor b1 b2)))
    (yield #f)))

;; sequence? sequence? -> sequence?
;; As per `xor-generator`, but returns a sequence suitable for use
;; with `for` etc.
(define (in-xor seq1 seq2) (in-producer (xor-generator seq1 seq2) #f))

;; bytes? exact-integer? sequence? -> sequence?
;; Returns a sequence of ciphertext (if given plaintext) or plaintext
;; (if given ciphertext) bytes corresponding to XORing of bytes from
;; `text-seq` with the RC4 stream corresponding to `key` and
;; `drop-count`.
(define (in-rc4 key drop-count text-seq)
  (in-xor (in-rc4-stream key drop-count) text-seq))
