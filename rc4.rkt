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

(define (sequence->bytes seq)
  (list->bytes (sequence->list seq)))

(define (sequence->bytes/length length seq)
  (define result (make-bytes length))
  (for ([(i b) (in-parallel length seq)])
    (bytes-set! result i b))
  result)

(define (swap! S i j)
  (define Sj (vector-ref S j))
  (vector-set! S j (vector-ref S i))
  (vector-set! S i Sj))

(define (truncate-to-byte n)
  (bitwise-and n 255))

;; The repeat-count is to accommodate CipherSaber-2.
(define (rc4-initialize key [repeat-count 1])
  (define keylength (bytes-length key))
  (define S (for/vector ([i 256]) i))
  (define j 0)
  (for ([_ repeat-count])
    (for ([i 256])
      (set! j (truncate-to-byte (+ j (vector-ref S i) (bytes-ref key (modulo i keylength)))))
      (swap! S i j)))
  S)

(define (rc4-stream-generator S drop-count)
  (define i 0)
  (define j 0)
  (define (round)
    (set! i (truncate-to-byte (+ i 1)))
    (set! j (truncate-to-byte (+ j (vector-ref S i))))
    (swap! S i j)
    (vector-ref S (truncate-to-byte (+ (vector-ref S i) (vector-ref S j)))))
  (for ([_ drop-count]) (round))
  round)

(define (in-rc4-stream* S drop-count) (in-producer (rc4-stream-generator S drop-count) #f))
(define (in-rc4-stream key drop-count) (in-rc4-stream* (rc4-initialize key) drop-count))

(define (xor-generator seq1 seq2)
  (generator ()
    (for ([(b1 b2) (in-parallel seq1 seq2)])
      (yield (bitwise-xor b1 b2)))
    (yield #f)))

(define (in-xor seq1 seq2) (in-producer (xor-generator seq1 seq2) #f))

(define (in-rc4 key drop-count text-seq)
  (in-xor (in-rc4-stream key drop-count) text-seq))
