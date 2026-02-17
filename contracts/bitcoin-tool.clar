;; bitcointool - Bitcoin Transaction Verifier for Stacks
;; This contract provides utility functions to verify Bitcoin transactions trustlessly.

;; Error Codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PROOF (err u101))
(define-constant ERR-DECODING-FAILED (err u102))
(define-constant ERR-INVALID-TX (err u103))
(define-constant ERR-OUT-OF-BOUNDS (err u104))
(define-constant ERR-UNKNOWN-SCRIPT-TYPE (err u105))

;; Script Types
(define-constant SCRIPT-P2PKH u1)
(define-constant SCRIPT-P2SH u2)
(define-constant SCRIPT-P2WPKH u3)
(define-constant SCRIPT-OP-RETURN u4)

;; --- Merkle Proof Verification ---

;; Returns true if the provided transaction hash is part of the Merkle root
(define-read-only (verify-merkle-proof (tx-hash (buff 32)) (merkle-root (buff 32)) (proof (list 20 (buff 32))) (index uint))
    (let
        (
            ;; Iteratively hash the proof nodes
            (final-hash (fold hash-merkle-step proof { hash: tx-hash, idx: index }))
        )
        (is-eq (get hash final-hash) merkle-root)
    )
)

(define-private (hash-merkle-step (proof-node (buff 32)) (state { hash: (buff 32), idx: uint }))
    (let
        (
            (current-hash (get hash state))
            (current-idx (get idx state))
            ;; In a Merkle tree, if the index is even, the node is on the right. If odd, it's on the left.
            (new-hash (if (is-eq (mod current-idx u2) u0)
                (sha256 (concat current-hash proof-node))
                (sha256 (concat proof-node current-hash))))
        )
        { hash: new-hash, idx: (/ current-idx u2) }
    )
)

;; --- Buffer Utilities ---

(define-read-only (extract-uint8 (data (buff 1024)) (offset uint))
    (let
        (
            (byte (element-at data offset))
        )
        (ok (unwrap! byte ERR-OUT-OF-BOUNDS))
    )
)

(define-read-only (extract-uint32-le (data (buff 1024)) (offset uint))
    (let
        (
            (b0 (unwrap! (element-at data offset) ERR-OUT-OF-BOUNDS))
            (b1 (unwrap! (element-at data (+ offset u1)) ERR-OUT-OF-BOUNDS))
            (b2 (unwrap! (element-at data (+ offset u2)) ERR-OUT-OF-BOUNDS))
            (b3 (unwrap! (element-at data (+ offset u3)) ERR-OUT-OF-BOUNDS))
        )
        (ok (+ (* (buff-to-uint-be b3) u16777216)
               (+ (* (buff-to-uint-be b2) u65536)
                  (+ (* (buff-to-uint-be b1) u256)
                     (buff-to-uint-be b0)))))
    )
)

;; --- Buffer Reverse ---

;; Helper to swap endianness (Bitcoin uses Little-Endian for many fields)
(define-read-only (reverse-buff32 (input (buff 32)))
    (let
        (
            (b0 (unwrap-panic (element-at input u0))) (b1 (unwrap-panic (element-at input u1)))
            (b2 (unwrap-panic (element-at input u2))) (b3 (unwrap-panic (element-at input u3)))
            (b4 (unwrap-panic (element-at input u4))) (b5 (unwrap-panic (element-at input u5)))
            (b6 (unwrap-panic (element-at input u6))) (b7 (unwrap-panic (element-at input u7)))
            (b8 (unwrap-panic (element-at input u8))) (b9 (unwrap-panic (element-at input u9)))
            (b10 (unwrap-panic (element-at input u10))) (b11 (unwrap-panic (element-at input u11)))
            (b12 (unwrap-panic (element-at input u12))) (b13 (unwrap-panic (element-at input u13)))
            (b14 (unwrap-panic (element-at input u14))) (b15 (unwrap-panic (element-at input u15)))
            (b16 (unwrap-panic (element-at input u16))) (b17 (unwrap-panic (element-at input u17)))
            (b18 (unwrap-panic (element-at input u18))) (b19 (unwrap-panic (element-at input u19)))
            (b20 (unwrap-panic (element-at input u20))) (b21 (unwrap-panic (element-at input u21)))
            (b22 (unwrap-panic (element-at input u22))) (b23 (unwrap-panic (element-at input u23)))
            (b24 (unwrap-panic (element-at input u24))) (b25 (unwrap-panic (element-at input u25)))
            (b26 (unwrap-panic (element-at input u26))) (b27 (unwrap-panic (element-at input u27)))
            (b28 (unwrap-panic (element-at input u28))) (b29 (unwrap-panic (element-at input u29)))
            (b30 (unwrap-panic (element-at input u30))) (b31 (unwrap-panic (element-at input u31)))
        )
        (concat (concat (concat (concat b31 b30) (concat b29 b28)) (concat (concat b27 b26) (concat b25 b24)))
                (concat (concat (concat b23 b22) (concat b21 b20)) (concat (concat b19 b18) (concat b17 b16)))
                (concat (concat (concat b15 b14) (concat b13 b12)) (concat (concat b11 b10) (concat b9 b8)))
                (concat (concat (concat b7 b6) (concat b5 b4)) (concat (concat b3 b2) (concat b1 b0))))
    )
)

;; --- Transaction Parsing Functions ---

(define-read-only (extract-tx-ins-count (tx-raw (buff 1024)))
    ;; In a simple Bitcoin TX, the ins-count is at offset 4 (after 4-byte version)
    (extract-uint8 tx-raw u4)
)

(define-read-only (extract-tx-outs-count (tx-raw (buff 1024)))
    ;; Placeholder: Ideally skip inputs to find output count
    (ok u0)
)

(define-read-only (get-txid-from-raw (tx-raw (buff 1024)))
    (ok (sha256 (sha256 tx-raw)))
)

;; --- Script Identification ---

(define-read-only (is-p2pkh (script (buff 1024)))
    ;; P2PKH: OP_DUP OP_HASH160 <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    ;; Length is typically 25 bytes. Starts with 0x76a9 and ends with 0x88ac.
    (and 
        (is-eq (element-at script u0) (some 0x76))
        (is-eq (element-at script u1) (some 0xa9))
        (is-eq (element-at script u24) (some 0x88))
        (is-eq (element-at script u25) (some 0xac))
    )
)

(define-read-only (is-p2sh (script (buff 1024)))
    ;; P2SH: OP_HASH160 <ScriptHash> OP_EQUAL
    ;; Length 23 bytes. Starts with 0xa9 and ends with 0x87.
    (and 
        (is-eq (element-at script u0) (some 0xa9))
        (is-eq (element-at script u22) (some 0x87))
    )
)

(define-read-only (is-p2wpkh (script (buff 1024)))
    ;; P2WPKH: OP_0 <20-byte-key-hash>
    ;; Length 22 bytes. Starts with 0x0014.
    (and 
        (is-eq (element-at script u0) (some 0x00))
        (is-eq (element-at script u1) (some 0x14))
    )
)

;; --- Public API ---

;; Verifies that a transaction was included in a specific Bitcoin block
;; @param tx-hash-le: Transaction hash in Little-Endian (as seen in explorers)
;; @param merkle-root-le: Merkle root in Little-Endian
;; @param proof: List of sibling hashes in the Merkle tree
;; @param index: Leaf index of the transaction in the block
(define-public (verify-tx-inclusion 
    (tx-hash-le (buff 32)) 
    (merkle-root-le (buff 32)) 
    (proof (list 20 (buff 32))) 
    (index uint))
    (let
        (
            (tx-hash (reverse-buff32 tx-hash-le))
            (merkle-root (reverse-buff32 merkle-root-le))
            (is-valid (verify-merkle-proof tx-hash merkle-root proof index))
        )
        (if is-valid
            (ok true)
            ERR-INVALID-PROOF)
    )
)

(define-read-only (get-version) (ok "1.2.0"))
