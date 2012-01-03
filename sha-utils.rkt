#lang racket/base

(provide bitwise-rotate
	 bitwise-rotate32
	 add32
	 make-sha-driver
	 make-sha-hasher)

(define (bitwise-rotate n by0 limit)
  (define by (modulo by0 limit))
  (define mask (- (arithmetic-shift 1 limit) 1))
  (bitwise-ior (bitwise-and mask (arithmetic-shift n by))
	       (bitwise-and mask (arithmetic-shift n (- by limit)))))

(define (bitwise-rotate32 n by)
  (bitwise-rotate n by 32))

(define (add32 . args)
  (bitwise-and #xffffffff (apply + args)))

(define (make-sha-driver chunk-size process-chunk! final-values)
  (define buffer (make-bytes chunk-size 0))
  (define fill-pointer 0)
  (define input-length 0) ;; Total count of input bytes processed so far

  (define (accept-chunk bs [low 0] [high-arg #f])
    (if (eq? bs #f)
	(finalize)
	(accept-unaligned-bytes bs low (- (or high-arg (bytes-length bs)) low))))

  (define (process! bs offset)
    (set! input-length (+ input-length chunk-size))
    (process-chunk! bs offset))

  (define (finalize)
    (define padding (- chunk-size (modulo (+ 9 fill-pointer) chunk-size)))
    (bytes-set! buffer fill-pointer 128)
    (bytes-copy! buffer (+ fill-pointer 1) (make-bytes padding 0))
    (integer->integer-bytes (* 8 (+ input-length fill-pointer))
			    8 #f #t buffer (- chunk-size 8))
    (process! buffer 0)
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
      (let ((contribution (min len (- chunk-size fill-pointer))))
	(bytes-copy! buffer fill-pointer
		     bs low (+ low contribution))
	(set! fill-pointer (+ fill-pointer contribution))
	(when (= fill-pointer chunk-size)
	  (process! buffer 0)
	  (set! fill-pointer 0))
	(accept-unaligned-bytes bs (+ low contribution) (- len contribution)))]))

  (define (accept-aligned-bytes bs low len)
    (cond
     [(<= len 0)
      ;; no more input
      (void)]
     [(>= len chunk-size)
      ;; more than a chunk's worth
      (process! bs low)
      (accept-aligned-bytes bs (+ low chunk-size) (- len chunk-size))]
     [else
      ;; less than a chunk's worth
      (bytes-copy! buffer 0
		   bs low (+ low len))
      (set! fill-pointer len)]))

  accept-chunk)

(define (make-sha-hasher hash-maker)
  (lambda (bs [low 0] [high #f])
    (define hash (hash-maker))
    (hash bs low high)
    (hash #f)))
