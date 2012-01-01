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

(require racket/stream)
(require "rc4.rkt")

(provide ciphersaber-iv-length
	 random-bytes
	 in-ciphersaber-encrypt*
	 in-ciphersaber-encrypt
	 in-ciphersaber-decrypt*
	 in-ciphersaber-decrypt
	 ciphersaber-encrypt
	 ciphersaber-decrypt)

;; Length, in bytes, of the expected IVs for use with CipherSaber.
(define ciphersaber-iv-length 10)

;; exact-integer? -> bytes?
;; Returns a byte-vector of length `n` containing random bytes.
(define (random-bytes n)
  (list->bytes (for/list ([_ (in-range n)]) (random 256))))

;; bytes? exact-integer? exact-integer? sequence? -> sequence?
;; Performs RC4 (as initialized by the CipherSiber protocol) on `text-seq`.
(define (in-cs2 key init-count drop-count text-seq)
  (in-xor (in-rc4-stream* (rc4-initialize key init-count) drop-count) text-seq))

;; bytes? bytes? exact-integer? exact-integer? sequence? -> sequence?
;; Performs CipherSaber encryption with the given parameters. NOTE:
;; prepends the IV to the output bytes.
(define (in-ciphersaber-encrypt* key iv init-count drop-count plaintext-seq)
  (in-sequences (in-bytes iv)
		(in-cs2 (bytes-append key iv) init-count drop-count plaintext-seq)))

;; bytes? exact-integer? exact-integer? sequence? -> sequence?
;; Performs CipherSaber encryption with the given parameters, using a
;; fresh (random) IV. Prepends the IV to the output bytes.
(define (in-ciphersaber-encrypt key init-count drop-count plaintext-seq)
  (define iv (random-bytes ciphersaber-iv-length))
  (in-ciphersaber-encrypt* key iv init-count drop-count plaintext-seq))

;; bytes? bytes? exact-integer? exact-integer? sequence? -> sequence?
;; Performs CipherSaber decryption with the given parameters. Does NOT
;; expect the IV to be prepended to the input bytes.
(define (in-ciphersaber-decrypt* key iv init-count drop-count ciphertext-seq)
  (in-cs2 (bytes-append key iv) init-count drop-count ciphertext-seq))

;; bytes? bytes? exact-integer? exact-integer? sequence? -> sequence?
;; Performs CipherSaber decryption with the given parameters, taking
;; the IV from the first few input bytes.
(define (in-ciphersaber-decrypt key init-count drop-count iv-and-ciphertext-seq)
  (define iv-and-ciphertext (sequence->stream iv-and-ciphertext-seq))
  (define iv (sequence->bytes/length ciphersaber-iv-length iv-and-ciphertext))
  (define ciphertext-seq (stream-tail iv-and-ciphertext ciphersaber-iv-length))
  (in-ciphersaber-decrypt* key iv init-count drop-count ciphertext-seq))

;; bytes? exact-integer? exact-integer? bytes? -> bytes?
;; Encrypts the given plaintext with the given parameters.
(define (ciphersaber-encrypt key init-count drop-count plaintext)
  (define bs (if (bytes? plaintext) plaintext (string->bytes/utf-8 plaintext)))
  (sequence->bytes (in-ciphersaber-encrypt key init-count drop-count (in-bytes bs))))

;; bytes? exact-integer? exact-integer? bytes? -> bytes?
;; Decrypts the given ciphertext with the given parameters.
(define (ciphersaber-decrypt key init-count drop-count ciphertext)
  (define iv (subbytes ciphertext 0 ciphersaber-iv-length))
  (define ct (subbytes ciphertext ciphersaber-iv-length))
  (sequence->bytes (in-ciphersaber-decrypt* key iv init-count drop-count ct)))
