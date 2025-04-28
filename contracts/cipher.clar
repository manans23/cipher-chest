;; CipherChest 
;; This contract enables users to store, manage, and share digital assets with
;; cryptographic verification and time-based access controls

;; Error Code Definitions
(define-constant ERROR_BAD_PARAMETERS (err u301))
(define-constant ERROR_ASSET_MISSING (err u302))
(define-constant ERROR_ASSET_DUPLICATE (err u303))
(define-constant ERROR_DESCRIPTION_INVALID (err u304))
(define-constant ERROR_ACCESS_DENIED (err u305)) 
(define-constant ERROR_NOT_AUTHORIZED (err u300))
(define-constant ERROR_TIME_RANGE_INVALID (err u306))
(define-constant ERROR_PRIVILEGE_LEVEL_INVALID (err u307))
(define-constant ERROR_GROUP_INVALID (err u308))
(define-constant PLATFORM_ADMIN tx-sender)

;; Primary Data Storage Structures
;; Assets Registry - Stores all registered digital assets
(define-map asset-registry
    { asset-identifier: uint }
    {
        name: (string-ascii 50),
        creator: principal,
        digest: (string-ascii 64),
        description: (string-ascii 200),
        timestamp-created: uint,
        timestamp-updated: uint,
        classification: (string-ascii 20),
        tags: (list 5 (string-ascii 30))
    }
)

;; Access Privilege Constants
(define-constant PRIVILEGE_VIEW "read")
(define-constant PRIVILEGE_MODIFY "write")
(define-constant PRIVILEGE_FULL "admin")

;; System State Variables
(define-data-var asset-counter uint u0)

;; Access Control Registry - Manages permissioned access to assets
(define-map access-permissions
    { asset-identifier: uint, recipient: principal }
    {
        privilege-level: (string-ascii 10),
        timestamp-granted: uint,
        timestamp-expiration: uint,
        modification-allowed: bool
    }
)

;; ============== Validation Functions ==============

;; Validates that an asset name meets requirements
(define-private (is-valid-asset-name (name (string-ascii 50)))
    (and
        (> (len name) u0)
        (<= (len name) u50)
    )
)

;; Validates that a cryptographic digest is properly formatted
(define-private (is-valid-digest (digest (string-ascii 64)))
    (and
        (is-eq (len digest) u64)
        (> (len digest) u0)
    )
)

;; Validates that a set of tags is properly formatted
(define-private (is-valid-tag-collection (tags (list 5 (string-ascii 30))))
    (and
        (>= (len tags) u1)
        (<= (len tags) u5)
        (is-eq (len (filter is-valid-tag tags)) (len tags))
    )
)

;; Validates that an individual tag is properly formatted
(define-private (is-valid-tag (tag (string-ascii 30)))
    (and
        (> (len tag) u0)
        (<= (len tag) u30)
    )
)

;; Validates that an asset description is properly formatted
(define-private (is-valid-description (description (string-ascii 200)))
    (and
        (>= (len description) u1)
        (<= (len description) u200)
    )
)

;; Validates that an asset classification is properly formatted
(define-private (is-valid-classification (classification (string-ascii 20)))
    (and
        (>= (len classification) u1)
        (<= (len classification) u20)
    )
)

;; Validates that a privilege level is one of the allowed values
(define-private (is-valid-privilege-level (privilege-level (string-ascii 10)))
    (or
        (is-eq privilege-level PRIVILEGE_VIEW)
        (is-eq privilege-level PRIVILEGE_MODIFY)
        (is-eq privilege-level PRIVILEGE_FULL)
    )
)

;; Validates that an access duration is within acceptable limits
(define-private (is-valid-time-range (duration uint))
    (and
        (> duration u0)
        (<= duration u52560) ;; Maximum ~1 year in blocks
    )
)

;; Verifies that a recipient is not the same as the sender (no self-sharing)
(define-private (is-valid-recipient (recipient principal))
    (not (is-eq recipient tx-sender))
)

;; Checks if the specified user is the owner of a given asset
(define-private (is-asset-owner (asset-identifier uint) (user principal))
    (match (map-get? asset-registry { asset-identifier: asset-identifier })
        record (is-eq (get creator record) user)
        false
    )
)

;; Verifies that an asset with the given identifier exists
(define-private (does-asset-exist (asset-identifier uint))
    (is-some (map-get? asset-registry { asset-identifier: asset-identifier }))
)

;; Validates the modification permission flag
(define-private (is-valid-modification-permission (modification-allowed bool))
    (or (is-eq modification-allowed true) (is-eq modification-allowed false))
)

;; ============== Primary Asset Management Functions ==============

;; Create a new protected digital asset in the vault
(define-public (register-new-asset 
    (name (string-ascii 50))
    (digest (string-ascii 64))
    (description (string-ascii 200))
    (classification (string-ascii 20))
    (tags (list 5 (string-ascii 30)))
)
    (let
        (
            (next-id (+ (var-get asset-counter) u1))
            (current-block block-height)
        )
        ;; Verify all inputs meet formatting requirements
        (asserts! (is-valid-asset-name name) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-digest digest) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-description description) ERROR_DESCRIPTION_INVALID)
        (asserts! (is-valid-classification classification) ERROR_GROUP_INVALID)
        (asserts! (is-valid-tag-collection tags) ERROR_DESCRIPTION_INVALID)

        ;; Store the asset in the registry
        (map-set asset-registry
            { asset-identifier: next-id }
            {
                name: name,
                creator: tx-sender,
                digest: digest,
                description: description,
                timestamp-created: current-block,
                timestamp-updated: current-block,
                classification: classification,
                tags: tags
            }
        )

        ;; Increment the asset counter
        (var-set asset-counter next-id)
        (ok next-id)
    )
)

;; Modify an existing asset's information
(define-public (modify-existing-asset
    (asset-identifier uint)
    (updated-name (string-ascii 50))
    (updated-digest (string-ascii 64))
    (updated-description (string-ascii 200))
    (updated-tags (list 5 (string-ascii 30)))
)
    (let
        (
            (asset (unwrap! (map-get? asset-registry { asset-identifier: asset-identifier }) ERROR_ASSET_MISSING))
        )
        ;; Verify caller is authorized to modify this asset
        (asserts! (is-asset-owner asset-identifier tx-sender) ERROR_NOT_AUTHORIZED)

        ;; Validate all inputs
        (asserts! (is-valid-asset-name updated-name) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-digest updated-digest) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-description updated-description) ERROR_DESCRIPTION_INVALID)
        (asserts! (is-valid-tag-collection updated-tags) ERROR_DESCRIPTION_INVALID)

        ;; Update the asset record
        (map-set asset-registry
            { asset-identifier: asset-identifier }
            (merge asset {
                name: updated-name,
                digest: updated-digest,
                description: updated-description,
                timestamp-updated: block-height,
                tags: updated-tags
            })
        )
        (ok true)
    )
)

;; Grant access to an asset to another user
(define-public (grant-asset-access
    (asset-identifier uint)
    (recipient principal)
    (privilege-level (string-ascii 10))
    (duration uint)
    (modification-allowed bool)
)
    (let
        (
            (current-block block-height)
            (expiration-block (+ current-block duration))
        )
        ;; Validate all parameters
        (asserts! (does-asset-exist asset-identifier) ERROR_ASSET_MISSING)
        (asserts! (is-asset-owner asset-identifier tx-sender) ERROR_NOT_AUTHORIZED)
        (asserts! (is-valid-recipient recipient) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-privilege-level privilege-level) ERROR_PRIVILEGE_LEVEL_INVALID)
        (asserts! (is-valid-time-range duration) ERROR_TIME_RANGE_INVALID)
        (asserts! (is-valid-modification-permission modification-allowed) ERROR_BAD_PARAMETERS)

        ;; Record the access permission
        (map-set access-permissions
            { asset-identifier: asset-identifier, recipient: recipient }
            {
                privilege-level: privilege-level,
                timestamp-granted: current-block,
                timestamp-expiration: expiration-block,
                modification-allowed: modification-allowed
            }
        )
        (ok true)
    )
)

;; ============== Alternative Implementation Functions ==============

;; Enhanced version of the modify function with improved structure
(define-public (update-asset-details
    (asset-identifier uint)
    (updated-name (string-ascii 50))
    (updated-digest (string-ascii 64))
    (updated-description (string-ascii 200))
    (updated-tags (list 5 (string-ascii 30)))
)
    (let
        (
            (asset (unwrap! (map-get? asset-registry { asset-identifier: asset-identifier }) ERROR_ASSET_MISSING))
        )
        ;; Verify caller is the asset owner
        (asserts! (is-asset-owner asset-identifier tx-sender) ERROR_NOT_AUTHORIZED)

        ;; Create the updated asset record
        (let
            (
                (modified-asset (merge asset {
                    name: updated-name,
                    digest: updated-digest,
                    description: updated-description,
                    tags: updated-tags
                }))
            )
            ;; Update the registry
            (map-set asset-registry { asset-identifier: asset-identifier } modified-asset)
            (ok true)
        )
    )
)

;; Streamlined asset creation function with equivalent functionality
(define-public (create-protected-asset
    (name (string-ascii 50))
    (digest (string-ascii 64))
    (description (string-ascii 200))
    (classification (string-ascii 20))
    (tags (list 5 (string-ascii 30)))
)
    (let
        (
            (next-id (+ (var-get asset-counter) u1))
            (current-block block-height)
        )
        ;; Validate all input parameters
        (asserts! (is-valid-asset-name name) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-digest digest) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-description description) ERROR_DESCRIPTION_INVALID)
        (asserts! (is-valid-classification classification) ERROR_GROUP_INVALID)
        (asserts! (is-valid-tag-collection tags) ERROR_DESCRIPTION_INVALID)

        ;; Register the new asset in the system
        (map-set asset-registry
            { asset-identifier: next-id }
            {
                name: name,
                creator: tx-sender,
                digest: digest,
                description: description,
                timestamp-created: current-block,
                timestamp-updated: current-block,
                classification: classification,
                tags: tags
            }
        )

        ;; Update the system counter
        (var-set asset-counter next-id)
        (ok next-id)
    )
)

;; Security-enhanced asset update function with comprehensive validation
(define-public (secure-asset-update
    (asset-identifier uint)
    (updated-name (string-ascii 50))
    (updated-digest (string-ascii 64))
    (updated-description (string-ascii 200))
    (updated-tags (list 5 (string-ascii 30)))
)
    (let
        (
            (asset (unwrap! (map-get? asset-registry { asset-identifier: asset-identifier }) ERROR_ASSET_MISSING))
        )
        ;; Verify ownership and authorization
        (asserts! (is-asset-owner asset-identifier tx-sender) ERROR_NOT_AUTHORIZED)

        ;; Validate all input parameters thoroughly
        (asserts! (is-valid-asset-name updated-name) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-digest updated-digest) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-description updated-description) ERROR_DESCRIPTION_INVALID)
        (asserts! (is-valid-tag-collection updated-tags) ERROR_DESCRIPTION_INVALID)

        ;; Update the asset with new values while preserving existing metadata
        (map-set asset-registry
            { asset-identifier: asset-identifier }
            (merge asset {
                name: updated-name,
                digest: updated-digest,
                description: updated-description,
                timestamp-updated: block-height,
                tags: updated-tags
            })
        )
        (ok true)
    )
)

;; Alternative storage structure with the same capabilities but different naming
(define-map enhanced-asset-registry
    { asset-identifier: uint }
    {
        name: (string-ascii 50),
        creator: principal,
        digest: (string-ascii 64),
        description: (string-ascii 200),
        timestamp-created: uint,
        timestamp-updated: uint,
        classification: (string-ascii 20),
        tags: (list 5 (string-ascii 30))
    }
)

;; Another implementation of asset creation using the enhanced registry
(define-public (create-asset-enhanced
    (name (string-ascii 50))
    (digest (string-ascii 64))
    (description (string-ascii 200))
    (classification (string-ascii 20))
    (tags (list 5 (string-ascii 30)))
)
    (let
        (
            (next-id (+ (var-get asset-counter) u1))
            (current-block block-height)
        )
        ;; Comprehensive validation of all inputs
        (asserts! (is-valid-asset-name name) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-digest digest) ERROR_BAD_PARAMETERS)
        (asserts! (is-valid-description description) ERROR_DESCRIPTION_INVALID)
        (asserts! (is-valid-classification classification) ERROR_GROUP_INVALID)
        (asserts! (is-valid-tag-collection tags) ERROR_DESCRIPTION_INVALID)

        ;; Store the asset in the enhanced registry
        (map-set enhanced-asset-registry
            { asset-identifier: next-id }
            {
                name: name,
                creator: tx-sender,
                digest: digest,
                description: description,
                timestamp-created: current-block,
                timestamp-updated: current-block,
                classification: classification,
                tags: tags
            }
        )

        ;; Update the system counter to reflect the new asset
        (var-set asset-counter next-id)
        (ok next-id)
    )
)

