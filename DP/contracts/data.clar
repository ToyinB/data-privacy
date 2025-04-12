;; Data Privacy Contract
;; This contract manages privacy settings and data access for users on the Stacks blockchain

;; Constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-DATA-NOT-FOUND (err u101))
(define-constant ERR-INVALID-PERMISSION (err u102))
(define-constant ERR-ALREADY-EXISTS (err u103))
(define-constant ERR-EXPIRED-ACCESS (err u104))
(define-constant ERR-INVALID-BLOCK-HEIGHT (err u105))
(define-constant ERR-INVALID-INPUT (err u106))
(define-constant ERR-INVALID-DATA-ID (err u107))
(define-constant ERR-INVALID-DATA (err u108))
(define-constant ERR-INVALID-DATA-TYPE (err u109))

;; Permission type constants (using string-ascii for consistency)
(define-constant PERMISSION-READ "read")
(define-constant PERMISSION-WRITE "write")
(define-constant PERMISSION-ADMIN "admin")
(define-constant PERMISSION-NONE "none")

;; Action type constants
(define-constant ACTION-READ "read")
(define-constant ACTION-CREATE "create")
(define-constant ACTION-UPDATE "update")
(define-constant ACTION-DELETE "delete")
(define-constant ACTION-GRANT "grant")
(define-constant ACTION-REVOKE "revoke")
(define-constant ACTION-DELETE-REQ "delete-req")

;; Data structures

;; Data entry structure - stores actual data with an associated type
(define-map data-entries
  { owner: principal, data-id: (string-ascii 36) }
  { 
    data: (string-ascii 1024),
    data-type: (string-ascii 64),
    encrypted: bool,
    created-at: uint,
    last-modified: uint
  }
)

;; Permission types: "read", "write", "admin"
(define-map data-permissions
  { data-owner: principal, data-id: (string-ascii 36), granted-to: principal }
  {
    permission-type: (string-ascii 10),
    expiration: uint, ;; Block height for expiration, 0 means no expiration
    revocable: bool
  }
)

;; Data access log for auditing
(define-map access-logs
  { data-owner: principal, data-id: (string-ascii 36), accessed-at: uint }
  {
    accessed-by: principal,
    action: (string-ascii 10)
  }
)

;; User privacy settings
(define-map user-privacy-settings
  { user: principal }
  {
    default-permission: (string-ascii 10),
    enable-logging: bool,
    encrypt-by-default: bool
  }
)

;; Private functions

;; Validate permission type
(define-private (is-valid-permission-type (permission-type (string-ascii 10)))
  (or 
    (is-eq permission-type PERMISSION-READ)
    (is-eq permission-type PERMISSION-WRITE)
    (is-eq permission-type PERMISSION-ADMIN)
    (is-eq permission-type PERMISSION-NONE)
  )
)

;; Validate data ID (check for non-empty string)
(define-private (is-valid-data-id (data-id (string-ascii 36)))
  (> (len data-id) u0)
)

;; Check if a principal has permission to perform an action on data
(define-private (has-permission (owner principal) (data-id (string-ascii 36)) (accessor principal) (required-permission (string-ascii 10)))
  (let (
    (permission-data (map-get? data-permissions { data-owner: owner, data-id: data-id, granted-to: accessor }))
    (is-owner (is-eq owner accessor))
  )
    (if is-owner
      true
      (if (is-none permission-data)
        false
        (let (
          (permission (get permission-type (unwrap-panic permission-data)))
          (expiration (get expiration (unwrap-panic permission-data)))
          (current-height block-height)
        )
          (and
            ;; Check if permission is admin (grants all access) or matches required permission
            (or (is-eq permission PERMISSION-ADMIN) (is-eq permission required-permission))
            ;; Check if permission is not expired (expiration of 0 means no expiration)
            (or (is-eq expiration u0) (> expiration current-height))
          )
        )
      )
    )
  )
)

;; Log an access attempt
(define-private (record-access (owner principal) (data-id (string-ascii 36)) (accessor principal) (action (string-ascii 10)))
  (let (
    (user-settings (default-to 
                    { default-permission: PERMISSION-NONE, enable-logging: true, encrypt-by-default: false } 
                    (map-get? user-privacy-settings { user: owner })))
    (should-log (get enable-logging user-settings))
  )
    (if should-log
      (map-set access-logs 
        { data-owner: owner, data-id: data-id, accessed-at: block-height }
        { accessed-by: accessor, action: action }
      )
      true
    )
  )
)

;; Public functions

;; Initialize user privacy settings
(define-public (initialize-privacy-settings (default-permission (string-ascii 10)) (enable-logging bool) (encrypt-by-default bool))
  (let (
    (caller tx-sender)
    (existing-settings (map-get? user-privacy-settings { user: caller }))
  )
    ;; Validate permission type
    (asserts! (is-valid-permission-type default-permission) ERR-INVALID-PERMISSION)
    
    (map-set user-privacy-settings
      { user: caller }
      { 
        default-permission: default-permission,
        enable-logging: enable-logging,  ;; Bool type is safe
        encrypt-by-default: encrypt-by-default  ;; Bool type is safe
      }
    )
    (ok true)
  )
)

;; Store data in the contract
(define-public (store-data (data-id (string-ascii 36)) (data (string-ascii 1024)) (data-type (string-ascii 64)) (encrypted bool))
  (let (
    (caller tx-sender)
    ;; Validate inputs
    (valid-data-id (is-valid-data-id data-id))
    (valid-data (> (len data) u0))
    (valid-data-type (> (len data-type) u0))
  )
    ;; Assert valid inputs
    (asserts! valid-data-id ERR-INVALID-DATA-ID)
    (asserts! valid-data ERR-INVALID-DATA)
    (asserts! valid-data-type ERR-INVALID-DATA-TYPE)
    
    (let (
      (existing-entry (map-get? data-entries { owner: caller, data-id: data-id }))
      (user-settings (default-to 
                      { default-permission: PERMISSION-NONE, enable-logging: true, encrypt-by-default: false } 
                      (map-get? user-privacy-settings { user: caller })))
      (should-encrypt (if encrypted encrypted (get encrypt-by-default user-settings)))
    )
      ;; Check if data entry already exists
      (if (is-some existing-entry)
        ;; Update existing data
        (begin
          (map-set data-entries
            { owner: caller, data-id: data-id }
            { 
              data: data,
              data-type: data-type,
              encrypted: should-encrypt,
              created-at: (get created-at (unwrap-panic existing-entry)),
              last-modified: block-height
            }
          )
          (record-access caller data-id caller ACTION-UPDATE)
          (ok true)
        )
        ;; Create new data entry
        (begin
          (map-set data-entries
            { owner: caller, data-id: data-id }
            { 
              data: data,
              data-type: data-type,
              encrypted: should-encrypt,
              created-at: block-height,
              last-modified: block-height
            }
          )
          (record-access caller data-id caller ACTION-CREATE)
          (ok true)
        )
      )
    )
  )
)

;; Retrieve data if authorized
(define-public (get-data (owner principal) (data-id (string-ascii 36)))
  (let (
    (caller tx-sender)
    ;; Validate data-id
    (valid-data-id (is-valid-data-id data-id))
  )
    ;; Assert valid input
    (asserts! valid-data-id ERR-INVALID-DATA-ID)
    
    (let (
      (data-entry (map-get? data-entries { owner: owner, data-id: data-id }))
    )
      ;; Verify data exists
      (asserts! (is-some data-entry) ERR-DATA-NOT-FOUND)
      
      ;; Check read permission
      (asserts! (has-permission owner data-id caller PERMISSION-READ) ERR-NOT-AUTHORIZED)
      
      ;; Log the access
      (record-access owner data-id caller ACTION-READ)
      
      ;; Return the data
      (ok (unwrap-panic data-entry))
    )
  )
)

;; Delete data
(define-public (delete-data (data-id (string-ascii 36)))
  (let (
    (caller tx-sender)
    ;; Validate data-id
    (valid-data-id (is-valid-data-id data-id))
  )
    ;; Assert valid input
    (asserts! valid-data-id ERR-INVALID-DATA-ID)
    
    (let (
      (data-entry (map-get? data-entries { owner: caller, data-id: data-id }))
    )
      ;; Verify data exists
      (asserts! (is-some data-entry) ERR-DATA-NOT-FOUND)
      
      ;; Delete the data
      (map-delete data-entries { owner: caller, data-id: data-id })
      
      ;; Log the deletion
      (record-access caller data-id caller ACTION-DELETE)
      
      (ok true)
    )
  )
)

;; Grant permission to another principal
(define-public (grant-permission (data-id (string-ascii 36)) (grantee principal) (permission-type (string-ascii 10)) (expiration uint) (revocable bool))
  (let (
    (caller tx-sender)
    ;; Validate inputs
    (valid-data-id (is-valid-data-id data-id))
    (valid-permission (is-valid-permission-type permission-type))
    (current-height block-height)
  )
    ;; Assert valid inputs
    (asserts! valid-data-id ERR-INVALID-DATA-ID)
    (asserts! valid-permission ERR-INVALID-PERMISSION)
    ;; Verify expiration is in the future or 0 (no expiration)
    (asserts! (or (is-eq expiration u0) (> expiration current-height)) ERR-INVALID-BLOCK-HEIGHT)
    
    (let (
      (data-entry (map-get? data-entries { owner: caller, data-id: data-id }))
    )
      ;; Verify data exists
      (asserts! (is-some data-entry) ERR-DATA-NOT-FOUND)
      
      ;; Set permission
      (map-set data-permissions
        { data-owner: caller, data-id: data-id, granted-to: grantee }
        {
          permission-type: permission-type,
          expiration: expiration,
          revocable: revocable  ;; Bool type is safe
        }
      )
      
      ;; Log the permission grant
      (record-access caller data-id caller ACTION-GRANT)
      
      (ok true)
    )
  )
)

;; Revoke permission
(define-public (revoke-permission (data-id (string-ascii 36)) (grantee principal))
  (let (
    (caller tx-sender)
    ;; Validate data-id
    (valid-data-id (is-valid-data-id data-id))
  )
    ;; Assert valid input
    (asserts! valid-data-id ERR-INVALID-DATA-ID)
    
    (let (
      (permission-data (map-get? data-permissions { data-owner: caller, data-id: data-id, granted-to: grantee }))
    )
      ;; Verify permission exists
      (asserts! (is-some permission-data) ERR-DATA-NOT-FOUND)
      
      ;; Verify permission is revocable
      (asserts! (get revocable (unwrap-panic permission-data)) ERR-NOT-AUTHORIZED)
      
      ;; Delete permission
      (map-delete data-permissions { data-owner: caller, data-id: data-id, granted-to: grantee })
      
      ;; Log the revocation
      (record-access caller data-id caller ACTION-REVOKE)
      
      (ok true)
    )
  )
)

;; Get all permissions for a data entry
(define-public (get-permission-status (owner principal) (data-id (string-ascii 36)) (accessor principal))
  (let (
    (caller tx-sender)
    ;; Validate data-id
    (valid-data-id (is-valid-data-id data-id))
  )
    ;; Assert valid input
    (asserts! valid-data-id ERR-INVALID-DATA-ID)
    
    (let (
      (permission-data (map-get? data-permissions { data-owner: owner, data-id: data-id, granted-to: accessor }))
    )
      ;; Only the data owner or the permission holder can check permission status
      (asserts! (or (is-eq caller owner) (is-eq caller accessor)) ERR-NOT-AUTHORIZED)
      
      ;; Create a type that will be consistent for both branches
      (ok (if (is-some permission-data)
           (let (
             (permission (unwrap-panic permission-data))
             (current-height block-height)
             (expiration (get expiration permission))
             (is-expired (and (> expiration u0) (>= current-height expiration)))
           )
             (if is-expired
               { has-permission: false, permission-info: permission }
               { has-permission: true, permission-info: permission }
             )
           )
           { has-permission: false, permission-info: 
             {
               permission-type: PERMISSION-NONE,
               expiration: u0,
               revocable: false
             }
           }
         ))
    )
  )
)

;; Get access logs for a specific data entry
(define-public (get-access-logs (data-id (string-ascii 36)) (start-block uint) (end-block uint))
  (let (
    (caller tx-sender)
    ;; Validate data-id and block range
    (valid-data-id (is-valid-data-id data-id))
    (valid-range (>= end-block start-block))
  )
    ;; Assert valid inputs
    (asserts! valid-data-id ERR-INVALID-DATA-ID)
    (asserts! valid-range ERR-INVALID-BLOCK-HEIGHT)
    
    (let (
      (data-entry (map-get? data-entries { owner: caller, data-id: data-id }))
    )
      ;; Only the data owner can access logs
      (asserts! (is-some data-entry) ERR-NOT-AUTHORIZED)
      
      ;; Return a response indicating success - actual implementation would require off-chain indexing
      ;; since Clarity doesn't support returning multiple map entries
      (ok { owner: caller, data-id: data-id, start-block: start-block, end-block: end-block })
    )
  )
)

;; Get user privacy settings
(define-public (get-privacy-settings)
  (let (
    (caller tx-sender)
    (settings (map-get? user-privacy-settings { user: caller }))
  )
    (if (is-some settings)
      (ok (unwrap-panic settings))
      (ok { default-permission: PERMISSION-NONE, enable-logging: true, encrypt-by-default: false })
    )
  )
)

;; Request data deletion from all holders of permissions
(define-public (request-data-deletion (data-id (string-ascii 36)))
  (let (
    (caller tx-sender)
    ;; Validate data-id
    (valid-data-id (is-valid-data-id data-id))
  )
    ;; Assert valid input
    (asserts! valid-data-id ERR-INVALID-DATA-ID)
    
    (let (
      (data-entry (map-get? data-entries { owner: caller, data-id: data-id }))
    )
      ;; Verify data exists
      (asserts! (is-some data-entry) ERR-DATA-NOT-FOUND)
      
      ;; Log the deletion request (actual implementation would require off-chain notification)
      (record-access caller data-id caller ACTION-DELETE-REQ)
      
      (ok true)
    )
  )
)

;; Update privacy settings
(define-public (update-privacy-settings (default-permission (string-ascii 10)) (enable-logging bool) (encrypt-by-default bool))
  (let (
    (caller tx-sender)
    ;; Validate permission type
    (valid-permission (is-valid-permission-type default-permission))
  )
    ;; Assert valid input
    (asserts! valid-permission ERR-INVALID-PERMISSION)
    
    (let (
      (existing-settings (map-get? user-privacy-settings { user: caller }))
    )  
      ;; Verify settings exist
      (asserts! (is-some existing-settings) ERR-DATA-NOT-FOUND)
      
      ;; Update settings
      (map-set user-privacy-settings
        { user: caller }
        { 
          default-permission: default-permission,
          enable-logging: enable-logging,  ;; Bool type is safe
          encrypt-by-default: encrypt-by-default  ;; Bool type is safe
        }
      )
      
      (ok true)
    )
  )
)
