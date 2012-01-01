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
