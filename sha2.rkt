#lang racket/base

(require (only-in racket/list take))
(require "sha-utils.rkt")
(require "primes.rkt")

(provide sha256-hash-size
	 sha256-chunk-size
	 make-sha256
	 sha256)

(define (sha2-h n)
  (bitwise-and #xffffffff (inexact->exact (truncate (* (expt 2 32) (sqrt n))))))

(define h0-init (sha2-h 2))
(define h1-init (sha2-h 3))
(define h2-init (sha2-h 5))
(define h3-init (sha2-h 7))
(define h4-init (sha2-h 11))
(define h5-init (sha2-h 13))
(define h6-init (sha2-h 17))
(define h7-init (sha2-h 19))

(define (sha2-k n)
  (bitwise-and #xffffffff (inexact->exact (truncate (* (expt 2 32) (expt n 1/3))))))

(define k (for/vector ([n (take first-primes 64)]) (sha2-k n)))

(define sha256-hash-size 32) ;; bytes
(define sha256-chunk-size 64) ;; bytes

(define (make-sha256)
  (define h0 h0-init)
  (define h1 h1-init)
  (define h2 h2-init)
  (define h3 h3-init)
  (define h4 h4-init)
  (define h5 h5-init)
  (define h6 h6-init)
  (define h7 h7-init)

  (define (process-chunk! chunk offset)
    (define w (make-vector 64 0))
    (for ([i 16])
      (define x (+ offset (* i 4)))
      (vector-set! w i (integer-bytes->integer chunk #f #t x (+ x 4))))
    (for ([i (in-range 16 64)])
      (define s0 (bitwise-xor (bitwise-rotate32 (vector-ref w (- i 15)) -7)
			      (bitwise-rotate32 (vector-ref w (- i 15)) -18)
			      (arithmetic-shift (vector-ref w (- i 15)) -3)))
      (define s1 (bitwise-xor (bitwise-rotate32 (vector-ref w (- i 2)) -17)
			      (bitwise-rotate32 (vector-ref w (- i 2)) -19)
			      (arithmetic-shift (vector-ref w (- i 2)) -10)))
      (vector-set! w i (add32 (vector-ref w (- i 16))
			      s0
			      (vector-ref w (- i 7))
			      s1)))

    (let loop ((i 0) (a h0) (b h1) (c h2) (d h3) (e h4) (f h5) (g h6) (h h7))
      (if (< i 64)
	  (let ((s0 (bitwise-xor (bitwise-rotate32 a -2)
				 (bitwise-rotate32 a -13)
				 (bitwise-rotate32 a -22)))
		(maj (bitwise-xor (bitwise-and a b)
				  (bitwise-and a c)
				  (bitwise-and b c)))
		(s1 (bitwise-xor (bitwise-rotate32 e -6)
				 (bitwise-rotate32 e -11)
				 (bitwise-rotate32 e -25)))
		(ch (bitwise-xor (bitwise-and e f)
				 (bitwise-and (bitwise-not e) g))))
	    (define t2 (add32 s0 maj))
	    (define t1 (add32 h s1 ch (vector-ref k i) (vector-ref w i)))
	    (loop (+ i 1) (add32 t1 t2) a b c (add32 d t1) e f g))
	  (begin (set! h0 (add32 h0 a))
		 (set! h1 (add32 h1 b))
		 (set! h2 (add32 h2 c))
		 (set! h3 (add32 h3 d))
		 (set! h4 (add32 h4 e))
		 (set! h5 (add32 h5 f))
		 (set! h6 (add32 h6 g))
		 (set! h7 (add32 h7 h))))))

  (define (final-values)
    (define result (make-bytes sha256-hash-size))
    (integer->integer-bytes h0 4 #f #t result 00)
    (integer->integer-bytes h1 4 #f #t result 04)
    (integer->integer-bytes h2 4 #f #t result 08)
    (integer->integer-bytes h3 4 #f #t result 12)
    (integer->integer-bytes h4 4 #f #t result 16)
    (integer->integer-bytes h5 4 #f #t result 20)
    (integer->integer-bytes h6 4 #f #t result 24)
    (integer->integer-bytes h7 4 #f #t result 28)
    result)

  (make-sha-driver sha256-chunk-size process-chunk! final-values))

;; sha256 : bytes? -> bytes?
;; Returns the SHA-256 hash of `bs` as a byte-vector of length
;; `sha256-hash-size`.
(define sha256 (make-sha-hasher make-sha256))
