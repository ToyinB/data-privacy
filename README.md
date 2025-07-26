# Data Privacy Contract

A comprehensive smart contract for the Stacks blockchain that enables users to store, manage, and control access to their personal data with advanced privacy features and permission management.

## Overview

This contract provides a decentralized solution for data privacy management, allowing users to:
- Store encrypted or plain text data on-chain
- Grant granular permissions to other users
- Track data access through audit logs
- Configure privacy settings per user
- Request data deletion compliance

## Key Features

### 🔐 Data Storage
- Store data entries with unique IDs and data types
- Optional encryption flag for sensitive information
- Automatic timestamping for creation and modification
- Support for data up to 1024 characters

### 🛡️ Permission Management
- **Read**: View data entries
- **Write**: Modify existing data
- **Admin**: Full access including permission management
- Time-based permission expiration
- Revocable permissions

### 📊 Privacy Controls
- User-configurable default permission levels
- Toggle access logging on/off
- Encrypt-by-default settings
- Comprehensive audit trails

### 🔍 Access Logging
- Track all data interactions (read, create, update, delete)
- Record permission grants and revocations
- Block height timestamps for all activities

## Usage

### Initialize Privacy Settings
```clarity
(initialize-privacy-settings "read" true false)
```
Set your default permission level, enable/disable logging, and encryption preferences.

### Store Data
```clarity
(store-data "user-profile-001" "John Doe, age 30" "profile" false)
```
Store data with a unique ID, content, data type, and encryption flag.

### Grant Permissions
```clarity
(grant-permission "user-profile-001" 'SP1ABC...XYZ "read" u1000 true)
```
Grant read permission to another user, expiring at block 1000, and revocable.

### Retrieve Data
```clarity
(get-data 'SP1OWNER...ABC "user-profile-001")
```
Access data if you have the required permissions.

### Revoke Permissions
```clarity
(revoke-permission "user-profile-001" 'SP1ABC...XYZ)
```
Remove previously granted permissions (if revocable).

## Permission Types

| Permission | Description |
|------------|-------------|
| `read` | View data entries |
| `write` | Modify existing data |
| `admin` | Full control including permission management |
| `none` | No access (default) |

## Error Codes

| Code | Error | Description |
|------|-------|-------------|
| 100 | ERR-NOT-AUTHORIZED | Insufficient permissions |
| 101 | ERR-DATA-NOT-FOUND | Data entry doesn't exist |
| 102 | ERR-INVALID-PERMISSION | Invalid permission type |
| 103 | ERR-ALREADY-EXISTS | Data entry already exists |
| 104 | ERR-EXPIRED-ACCESS | Permission has expired |
| 105 | ERR-INVALID-BLOCK-HEIGHT | Invalid expiration height |
| 106 | ERR-INVALID-INPUT | General input validation error |
| 107 | ERR-INVALID-DATA-ID | Invalid or empty data ID |
| 108 | ERR-INVALID-DATA | Invalid or empty data content |
| 109 | ERR-INVALID-DATA-TYPE | Invalid or empty data type |

## Security Features

- **Owner-only operations**: Data owners have full control over their entries
- **Time-based permissions**: Set expiration blocks for temporary access
- **Revocable permissions**: Ability to revoke access when needed
- **Audit logging**: Complete trail of all data interactions
- **Input validation**: Comprehensive validation of all inputs

## Data Structures

### Data Entry
```clarity
{
  data: (string-ascii 1024),
  data-type: (string-ascii 64),
  encrypted: bool,
  created-at: uint,
  last-modified: uint
}
```

### Permission Entry
```clarity
{
  permission-type: (string-ascii 10),
  expiration: uint,
  revocable: bool
}
```

### Privacy Settings
```clarity
{
  default-permission: (string-ascii 10),
  enable-logging: bool,
  encrypt-by-default: bool
}
```

## Best Practices

1. **Use unique data IDs**: Ensure data IDs are unique within your ownership scope
2. **Set appropriate expiration**: Use block heights for time-sensitive permissions
3. **Enable logging**: Keep audit trails for compliance and security
4. **Encrypt sensitive data**: Mark sensitive information as encrypted
5. **Regular permission review**: Periodically audit granted permissions

## Limitations

- Data size limited to 1024 characters
- Access logs require off-chain indexing for comprehensive retrieval
- Permission deletion notifications require off-chain implementation
- No built-in encryption (flag is for tracking purposes)
