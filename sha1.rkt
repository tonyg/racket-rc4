#lang racket/base

(require "sha-utils.rkt")

(provide sha1-hash-size
	 sha1-chunk-size
	 make-sha1
	 sha1)

(define (sha1-constant n)
  ;; "Nothing-up-my-sleeve" numbers
  ;; See http://en.wikipedia.org/wiki/SHA-1
  (inexact->exact (floor (* (expt 2 30) (sqrt n)))))

(define k1 (sha1-constant 2))
(define k2 (sha1-constant 3))
(define k3 (sha1-constant 5))
(define k4 (sha1-constant 10))

(define sha1-hash-size 20) ;; bytes
(define sha1-chunk-size 64) ;; bytes

;; Returns a stateful procedure that accepts either a byte-vector, in
;; which case it returns void, or #f, in which case it finishes the
;; hashing process and returns the computed hash as a byte-vector of
;; length `sha1-hash-size`. Call it repeatedly with chunks of the
;; input to hash, and then call it once with #f to finish. Once #f has
;; been given to the procedure, the procedure must not be called
;; again.
(define (make-sha1)
  (define h0 #x67452301)
  (define h1 #xEFCDAB89)
  (define h2 #x98BADCFE)
  (define h3 #x10325476)
  (define h4 #xC3D2E1F0)

  (define (process-chunk! chunk offset)
    (define w (make-vector 80 0))
    (for ([i 16])
      (define x (+ offset (* i 4)))
      (vector-set! w i (integer-bytes->integer chunk #f #t x (+ x 4))))
    (for ([i (in-range 16 80)])
      (vector-set! w i
		   (bitwise-rotate32 (bitwise-xor (vector-ref w (- i 3))
						  (vector-ref w (- i 8))
						  (vector-ref w (- i 14))
						  (vector-ref w (- i 16)))
				     1)))

    (let loop ((i 0) (a h0) (b h1) (c h2) (d h3) (e h4))
      (if (< i 80)
	  (let-values (((k f)
			(cond
			 [(<= 00 i 19) (values k1 (bitwise-ior (bitwise-and b c)
							       (bitwise-and (bitwise-not b) d)))]
			 [(<= 20 i 39) (values k2 (bitwise-xor b c d))]
			 [(<= 40 i 59) (values k3 (bitwise-ior (bitwise-and b c)
							       (bitwise-and b d)
							       (bitwise-and c d)))]
			 [(<= 60 i 79) (values k4 (bitwise-xor b c d))])))
	    (define new-a (add32 (bitwise-rotate32 a 5) f e k (vector-ref w i)))
	    (loop (+ i 1) new-a a (bitwise-rotate32 b 30) c d))
	  (begin (set! h0 (add32 h0 a))
		 (set! h1 (add32 h1 b))
		 (set! h2 (add32 h2 c))
		 (set! h3 (add32 h3 d))
		 (set! h4 (add32 h4 e))))))

  (define (final-values)
    (define result (make-bytes sha1-hash-size))
    (integer->integer-bytes h0 4 #f #t result 00)
    (integer->integer-bytes h1 4 #f #t result 04)
    (integer->integer-bytes h2 4 #f #t result 08)
    (integer->integer-bytes h3 4 #f #t result 12)
    (integer->integer-bytes h4 4 #f #t result 16)
    result)

  (make-sha-driver sha1-chunk-size process-chunk! final-values))

;; sha1 : bytes? -> bytes?
;; Returns the SHA-1 hash of `bs` as a byte-vector of length
;; `sha1-hash-size`.
(define sha1 (make-sha-hasher make-sha1))
