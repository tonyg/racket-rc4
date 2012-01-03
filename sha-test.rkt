#lang racket/base

(require rackunit)
(require "sha1.rkt")
(require "sha2.rkt")
(require "hex.rkt")

(define random-test-data
  (hex->bytes
   (string-append
    "2e8477365f48f4a5cb21f16e8ae15b757b463a8507e595de4f9d33d2103e"
    "ccde62d446afd6d218c1fb419fe9a5dc0237524f7c882583af7b7c544c47"
    "04fc84cd3ee84b1e8f93f6f0f0326ccd0c4a12e37878c50e48105a5e695f"
    "b621e1baa2c12068488cec8566c6b58cba3da320658a4aae23c53164bf03"
    "cc377cb80cb873d6b72439d68cc475409c465d1ab3cfec6069f063f31f25"
    "86489f2bf5efc18d776dc0014210c525c59e58c582476afa20618925e8ba"
    "641c93554e7a54dac50426b695d6c0dc1ab199e1406838ca582bf77fb755"
    "2f5d45cad75b175534f68e6ed9300b890e9c330c4b2db898f8519292962d"
    "d0784d2ae0160d055b63d102ca5b1a82ca450fb81e7c5d37c1a97c934f94"
    "f87176872787c3db736b88f285b21ad752b56e381ca018b0071692c54288"
    "44eb7cbb97c0bfafcbae5b6b4249d4ef78322da783fe0c3512b398c338d7"
    "402e47bac8a23f84199c7bf31f1e53222d7ee87d1f01e43f7f18d7f560e3"
    "c0f93956dd9bff640cbcc4947e197ec1cb6b8471f62eb21677a01b9d8655"
    "c752567c196cfdad1a4003064f6f09bf0bd7c9337ca15e1e3b3a22feb9c7"
    "c773613572c6a06ca397193fc80e07845f8b2edb3cc2741309eb828246f5"
    "e2a3ea321bf003aebfa37fda36ff0a3b2f79e6c6c6d61cd88dca09365440"
    "3eb7c6d162026c8b26d98fa94ef5f7d73c0d66f5cc2e6ce0df4c650e8c07"
    "6028c9016eb720a2ca9552b8cad35490a01337ffa276a60f9d3b51880281"
    "3b47168f8ec4b926cde7d049ab5fa32e21b8773c96c4426a0307386d5397"
    "337a595ab24eeb073a034bf9aaae66ed977cfde0b54f2b0035255ae92d82"
    "e77f780b2c21b4657e86842621f7fee7dc6bb54c11195aa721c7c8cd8583"
    "2f9228b6618dcac4be0bbda203b225c4172a6d4b65327769f9c0654df82e"
    "73f02df69398a7b5fbe65a33a94b46d2d2fa92e4d4a4e72cd412da9de5a5"
    "5f84fe6c30182cf4c9d61d05515857e8cba7767898c5868ca93b81044fda"
    "04ef97de6d1aa4b89b3ea30e7697fc0d5b57d3d1a5e8fc774c3038279c33"
    "aece015038e0b0b057b00dcb88ad47f3e817366bec992782ee9b0fb0df31"
    "ad21be0d5515c93608b8d4493d8645")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SHA-1 tests

(check-equal? (sha1 #"The quick brown fox jumps over the lazy dog")
	      (hex->bytes "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"))

(check-equal? (sha1 #"The quick brown fox jumps over the lazy cog")
	      (hex->bytes "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"))

(check-equal? (sha1 #"a")
	      (hex->bytes "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"))

(check-equal? (sha1 #"feedface" 5 6)
	      (hex->bytes "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"))

(check-equal? (sha1 #"")
	      (hex->bytes "da39a3ee5e6b4b0d3255bfef95601890afd80709"))

(check-equal? (sha1 random-test-data)
	      (hex->bytes "9dfa5a3d0bd4aa45d42276cce50ab083cad16791"))

(check-equal? (let ((s (make-sha1)))
		(for ([_ 10]) (s #"0123456789"))
		(s #f))
	      (hex->bytes "29b0e7878271645fffb7eec7db4a7473a1c00bc1"))

(check-equal? (let ((bs (make-bytes (* 2 sha1-chunk-size) 0))) (sha1 bs))
	      (hex->bytes "0ae4f711ef5d6e9d26c611fd2c8c8ac45ecbf9e7"))

(check-equal? (let ((bs (make-bytes sha1-chunk-size 0))
		    (s (make-sha1)))
		(for ([_ 2]) (s bs))
		(s #f))
	      (hex->bytes "0ae4f711ef5d6e9d26c611fd2c8c8ac45ecbf9e7"))

;; (check-equal? (let ((bs (make-bytes (* 2048 1024) 0)))
;;		(time (sha1 bs)))
;;	      (hex->bytes "7d76d48d64d7ac5411d714a4bb83f37e3e5b8df6"))

;; (check-equal? (let ((bs (make-bytes 1024 0))
;;		    (s (make-sha1)))
;;		(time
;;		 (for ([_ 2048]) (s bs))
;;		 (s #f)))
;;	      (hex->bytes "7d76d48d64d7ac5411d714a4bb83f37e3e5b8df6"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SHA-256 tests

(check-equal? (sha256 #"")
	      (hex->bytes "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

(check-equal? (sha256 #"The quick brown fox jumps over the lazy dog")
	      (hex->bytes "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"))

(check-equal? (sha256 #"The quick brown fox jumps over the lazy dog.")
	      (hex->bytes "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"))

(check-equal? (sha256 #"a")
	      (hex->bytes "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"))

(check-equal? (sha256 #"feedface" 5 6)
	      (hex->bytes "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"))

(check-equal? (sha256 random-test-data)
	      (hex->bytes "1791cf653a9ad7d7c88e48d55fd9bada27c62b8fa27befd8ed2e1f4d6e4e05a9"))

(check-equal? (let ((s (make-sha256)))
		(for ([_ 10]) (s #"0123456789"))
		(s #f))
	      (hex->bytes "9cfe7faff7054298ca87557e15a10262de8d3eee77827417fbdfea1c41b9ec23"))

;; (check-equal? (time (sha256 (make-bytes (* 2048 1024) 0)))
;;	      (hex->bytes "5647f05ec18958947d32874eeb788fa396a05d0bab7c1b71f112ceb7e9b31eee"))
