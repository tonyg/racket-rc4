#lang racket/base

(require rackunit)
(require racket/match)
(require "rc4.rkt")
(require "ciphersaber.rkt")
(require "hex.rkt")

(define ciphersaber-test-vectors
  `(
    ;; From http://ciphersaber.gurus.org/cstest.zip
    ((#"asdfg" 10 0 "ba9ab4cffb7700e618e382e8fcc5ab9813b1abc436ba7d5cdea1a31fb72fb5763c44cfc2ac77afee19ad")
     #"This is a test of CipherSaber-2.")

    ((#"asdfg" 1 0 "6f6d0babf3aa6719031530edb677ca74e0089dd0e7b8854356bb1448e37cdbefe7f3a84f4f5fb3fd")
     #"This is a test of CipherSaber.")

    ((#"SecretMessageforCongress" 1 0 "d4bb4d316807912a6a79a729fa9492fe3a55f5a9b6a0e55f0f0639c29765af617615b248fbdc53fa8e3669ed5ca0d8e680f3227bd89b4d1511ab9e97880b90c4df3820be012e372df4bf05c2a636277bc82a109d2663001e2e493074f745407ef06ca2aee120f033afc7afcb177a34426d760f0e957f6cc55eb90f4a7ed67b3f401aa117727499a04def16b63b9728adcaeca61bdca5b3126e99a6978ae92aa18e4d0237ca5e49968ee97ab32212d212d1d34d107f421c24457b411e17eade2ecdd44db1747ef87cf69cc0cdc1a9c47ca66e2edca273179cd6510188dcc7f748024cc35e9b1658d59f8ca096d7f918e737d182f0cb83da74eb3558aba87d3949f87410563c4abde8f9517ca676c7df5252c4ac2f3cc89e88cfe0d826070fb0e39c914fc878f3c1b94db99c1aaac31e58ee790d1f2c59ed3a21185e0ab5e8e0bedec9130b5492cf88607c4fe8395c4e381ce3da923d56ca8f9d60286d354bffe9f785025e7484044b7595111ccf57b93f9f9ae3754045d891f18412a3f0e403f7bb39141af71f2eb914863b32f2a53c27d263efb5b101d6f39282d43a3fc44b60b32b0d526617a6210497fa933a9e")
     #"The Fourth Amendment to the Constitution of the United States of America\r\n\r\n\"The right of the people to be secure in their persons, houses, papers, and \r\neffects, against unreasonable searches and seizures, shall not be violated, \r\nand no Warrants shall issue, but upon probable cause, supported by Oath or \r\naffirmation, and particularly describing the place to be searched, and the \r\npersons or things to be seized.\"\r\n")
    ))

(for ([vec (in-list ciphersaber-test-vectors)])
  (match vec
    [(list (list key init-count drop-count ciphertext-hex) plaintext)
     (check-equal? (ciphersaber-decrypt key init-count drop-count (hex->bytes ciphertext-hex))
		   plaintext)
     (define iv (hex->bytes (substring ciphertext-hex 0 20)))
     (check-equal?
      (sequence->bytes (in-ciphersaber-encrypt* key iv init-count drop-count plaintext))
      (hex->bytes ciphertext-hex))]))
