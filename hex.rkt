#lang racket/base

(require rackunit)
(require racket/list)

(provide hex->bytes
	 collect-hex)

(define (hex->bytes str)
  (list->bytes (for/list ([i (/ (string-length str) 2)])
		 (string->number (substring str (* i 2) (* (+ i 1) 2)) 16))))

(check-equal? (hex->bytes "01020304") (bytes 1 2 3 4))

(define (hex-digit n) (string-ref (number->string (bitwise-and n 15) 16) 0))
(define (collect-hex seq nbytes)
  (list->string (flatten (for/list ([(i b) (in-parallel nbytes seq)])
			   (list (hex-digit (arithmetic-shift b -4)) (hex-digit b))))))
