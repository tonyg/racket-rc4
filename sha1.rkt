#lang racket/base

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

(define (bitwise-rotate n by limit)
  (when (> by limit) (error 'bitwise-rotate "Rotate of ~v bits beyond limit of ~v bits" by limit))
  (define mask (- (arithmetic-shift 1 limit) 1))
  (bitwise-ior (bitwise-and mask (arithmetic-shift n by))
	       (bitwise-and mask (arithmetic-shift n (- by limit)))))

(define (bitwise-rotate32 n by)
  (bitwise-rotate n by 32))

(define (add32 . args)
  (bitwise-and #xffffffff (apply + args)))

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

  (define input-length 0)

  ;; Used to hold partial chunks
  (define buffer (make-bytes sha1-chunk-size #x5a)) ;; TODO -> 0
  (define fill-pointer 0)

  (define (accept-chunk bs [low 0] [high-arg #f])
    (if (eq? bs #f)
	(finalize)
	(accept-unaligned-bytes bs low (- (or high-arg (bytes-length bs)) low))))

  (define (finalize)
    (define padding (- sha1-chunk-size (modulo (+ 9 fill-pointer) sha1-chunk-size)))
    (bytes-set! buffer fill-pointer 128)
    (bytes-copy! buffer (+ fill-pointer 1) (make-bytes padding 0))
    (integer->integer-bytes (* 8 (+ input-length fill-pointer))
			    8 #f #t buffer (- sha1-chunk-size 8))
    (process-chunk! buffer 0)
    (final-values))

  (define (accept-unaligned-bytes bs low len)
    (cond
     [(zero? fill-pointer)
      ;; we are aligned at the start of a chunk
      (accept-aligned-bytes bs low len)]
     [(<= len 0)
      ;; no more input
      (void)]
     [else
      ;; we are regaining alignment
      (let ((contribution (min len (- sha1-chunk-size fill-pointer))))
	(bytes-copy! buffer fill-pointer
		     bs low (+ low contribution))
	(set! fill-pointer (+ fill-pointer contribution))
	(when (= fill-pointer sha1-chunk-size)
	  (process-chunk! buffer 0)
	  (set! fill-pointer 0))
	(accept-unaligned-bytes bs (+ low contribution) (- len contribution)))]))

  (define (accept-aligned-bytes bs low len)
    (cond
     [(<= len 0)
      ;; no more input
      (void)]
     [(>= len sha1-chunk-size)
      ;; more than a chunk's worth
      (process-chunk! bs low)
      (accept-aligned-bytes bs (+ low sha1-chunk-size) (- len sha1-chunk-size))]
     [else
      ;; less than a chunk's worth
      (bytes-copy! buffer 0
		   bs low (+ low len))
      (set! fill-pointer len)]))

  (define (process-chunk! chunk offset)
    (set! input-length (+ input-length sha1-chunk-size))

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

    (define a h0)
    (define b h1)
    (define c h2)
    (define d h3)
    (define e h4)

    (for ([i 80])
      (define-values (k f)
	(cond
	 [(<= 00 i 19) (values k1 (bitwise-ior (bitwise-and b c)
					       (bitwise-and (bitwise-not b) d)))]
	 [(<= 20 i 39) (values k2 (bitwise-xor b c d))]
	 [(<= 40 i 59) (values k3 (bitwise-ior (bitwise-and b c)
					       (bitwise-and b d)
					       (bitwise-and c d)))]
	 [(<= 60 i 79) (values k4 (bitwise-xor b c d))]))

      (define temp (add32 (bitwise-rotate32 a 5) f e k (vector-ref w i)))
      (set! e d)
      (set! d c)
      (set! c (bitwise-rotate32 b 30))
      (set! b a)
      (set! a temp))

    (set! h0 (add32 h0 a))
    (set! h1 (add32 h1 b))
    (set! h2 (add32 h2 c))
    (set! h3 (add32 h3 d))
    (set! h4 (add32 h4 e)))

  (define (final-values)
    (define result (make-bytes sha1-hash-size))
    (integer->integer-bytes h0 4 #f #t result 00)
    (integer->integer-bytes h1 4 #f #t result 04)
    (integer->integer-bytes h2 4 #f #t result 08)
    (integer->integer-bytes h3 4 #f #t result 12)
    (integer->integer-bytes h4 4 #f #t result 16)
    result)

  accept-chunk)

;; sha1 : bytes? -> bytes?
;; Returns the SHA-1 hash of `bs` as a byte-vector of length
;; `sha1-hash-size`.
(define (sha1 bs)
  (define s (make-sha1))
  (s bs)
  (s #f))
