;; bitcointool - Bitcoin Transaction Verifier for Stacks
;; This contract provides utility functions to verify Bitcoin transactions trustlessly.

;; Error Codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PROOF (err u101))
(define-constant ERR-DECODING-FAILED (err u102))
(define-constant ERR-INVALID-TX (err u103))
(define-constant ERR-OUT-OF-BOUNDS (err u104))
(define-constant ERR-UNKNOWN-SCRIPT-TYPE (err u105))

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

;; --- Bitcoin Transaction Parsing (Basic) ---

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
