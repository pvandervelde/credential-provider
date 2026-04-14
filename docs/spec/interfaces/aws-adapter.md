# AWS Adapter

**Architectural layer:** Adapters (`credential-provider`)
**Source file:** `credential-provider/src/aws.rs`
**Feature flag:** `aws`
**External dependencies:** `aws-config 1`, `aws-credential-types 1`

The AWS adapter wraps `aws-config` to resolve AWS credentials and supply them
as `AwsCredentials` values. It delegates to the standard AWS credential chain,
which handles environment detection automatically.

---

## `AwsCredentials`

### Location

`credential-provider/src/aws.rs`

### Purpose

AWS credentials value type. Defined in `credential-provider` (not core) because
it wraps AWS SDK types. Implements `Credential` so it can be used with
`CachingCredentialProvider`.

### Fields (private)

| Field | Type | Description |
|---|---|---|
| `inner` | `aws_credential_types::Credentials` | The underlying AWS SDK credentials value |
| `expires_at` | `Option<Instant>` | Expiry derived from the credential source |

### Public accessor: `inner()`

```rust
pub fn inner(&self) -> &aws_credential_types::Credentials
```

Returns a reference to the underlying AWS credential value for use with the
AWS SDK when constructing service clients (e.g., `aws-sdk-s3`, `aws-sdk-sqs`).

### `Credential` implementation

- `is_valid()`: `expires_at.map_or(true, |e| Instant::now() < e)`
- `expires_at()`: returns the stored expiry

Long-lived IAM access key credentials have no expiry; STS-issued temporary
credentials (AssumeRole, instance profile, EKS service account) carry an expiry.

### Clone

Derived. `aws_credential_types::Credentials` implements `Clone`.

---

## `AwsCredentialProvider`

### Location

`credential-provider/src/aws.rs`

### Purpose

A `CredentialProvider<AwsCredentials>` that resolves credentials via the
standard AWS credential chain. Used by `queue-runtime`'s SQS adapter.

### Fields (private)

| Field | Type | Description |
|---|---|---|
| `config` | `aws_config::SdkConfig` | Loaded AWS SDK configuration |

### Constructor: `new()` (async)

```rust
pub async fn new() -> Result<Self, CredentialError>
```

**Async because:** Loading the AWS configuration may involve network calls
(IMDS for instance profile, STS for role assumption).

**Behaviour:**

1. Calls `aws_config::load_from_env().await` to load the SDK config
2. Returns `CredentialError::Configuration` if no credential source is found

**Example:**

```rust
use credential_provider::aws::AwsCredentialProvider;

let provider = AwsCredentialProvider::new().await?;
```

---

## `get()` Behaviour

1. Extract the credential provider from `self.config`
2. Call `.provide_credentials().await`
3. Convert the result to `AwsCredentials`:
   - Map `expiry` (if any) from `SystemTime` to `Instant`
4. Return the `AwsCredentials` value

### Credential Chain Order

The AWS SDK resolves credentials in the following order:

1. IAM role assigned to the compute resource (EC2 instance profile, ECS task
   role, EKS pod service account via IRSA)
2. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
   `AWS_SESSION_TOKEN`)
3. `~/.aws/credentials` and `~/.aws/config`
4. Instance Metadata Service (IMDS v2)

---

## Error Mapping

| AWS condition | `CredentialError` variant |
|---|---|
| No credential source found | `Configuration("aws: no credential source: {detail}")` |
| IMDS / STS endpoint unreachable | `Unreachable("aws: {detail}")` |
| STS returned an error response | `Backend("aws: {detail}")` |
| Credential resolved but expired | `Revoked` |

---

## Usage Pattern

```rust
use std::{sync::Arc, time::Duration};
use credential_provider::aws::AwsCredentialProvider;
use credential_provider_core::CachingCredentialProvider;

let provider = Arc::new(CachingCredentialProvider::new(
    AwsCredentialProvider::new().await?,
    Duration::from_secs(300),
));

let creds = provider.get().await?;
// Pass creds.inner() to AWS SDK client constructors
```
