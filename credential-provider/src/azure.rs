// SPEC: docs/spec/interfaces/azure-adapter.md
//
// This module is gated behind the `azure` feature flag.
#![allow(dead_code, unused_variables)]

use azure_identity::DefaultAzureCredential;
use credential_provider_core::{BearerToken, BoxFuture, CredentialError, CredentialProvider};

/// A [`CredentialProvider<BearerToken>`] that delegates to the Azure Identity
/// credential chain.
///
/// `AzureCredentialProvider` wraps `azure-identity`'s `DefaultAzureCredential`
/// to supply `BearerToken` credentials for Azure service authentication. It is
/// the recommended provider when the service runs in an Azure environment and
/// needs to authenticate to Azure-managed resources.
///
/// # Credential Chain
///
/// Azure Identity resolves credentials in the following order:
/// 1. Managed identity (when running on Azure infrastructure — VMs, App Service,
///    AKS, etc.)
/// 2. Workload identity (Kubernetes workload identity federation)
/// 3. Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, etc.)
/// 4. Azure CLI (for local development — `az login`)
///
/// No configuration change is required when moving between local development
/// and Azure deployment.
///
/// # Authentication
///
/// The provider manages the Azure token acquisition internally via
/// `DefaultAzureCredential`. Unlike the Vault provider, callers do not need to
/// pre-authenticate. However, the environment must be configured appropriately
/// for the relevant chain entry (managed identity must be assigned, workload
/// identity binding must exist, etc.).
///
/// # Token Expiry
///
/// The returned `BearerToken` carries the expiry from the Azure token response.
/// `CachingCredentialProvider` will schedule renewal before expiry using its
/// configured `refresh_before_expiry` window.
///
/// # Errors
///
/// | Azure Identity condition              | `CredentialError` variant      |
/// |---------------------------------------|-------------------------------|
/// | No credential source found            | `Configuration("…")`          |
/// | Token endpoint unreachable            | `Unreachable("…")`            |
/// | Token endpoint returned error         | `Backend("…")`                |
///
/// # Examples
///
/// ```rust,ignore
/// use credential_provider::azure::AzureCredentialProvider;
///
/// let provider = AzureCredentialProvider::new(
///     "https://servicebus.azure.net/.default",
/// );
/// ```
///
/// See: docs/spec/interfaces/azure-adapter.md
pub struct AzureCredentialProvider {
    /// The OAuth2 scope for the target Azure resource
    /// (e.g. `"https://servicebus.azure.net/.default"`).
    scope: String,
    credential: DefaultAzureCredential,
}

impl AzureCredentialProvider {
    /// Creates a new provider that requests tokens for the given OAuth2 `scope`.
    ///
    /// # Parameters
    ///
    /// - `scope` — the OAuth2 scope URI for the target Azure resource. Must
    ///   end with `"/.default"` for managed identity flows.
    pub fn new(scope: impl Into<String>) -> Self {
        unimplemented!("See docs/spec/interfaces/azure-adapter.md")
    }
}

impl CredentialProvider<BearerToken> for AzureCredentialProvider {
    fn get(&self) -> BoxFuture<'_, Result<BearerToken, CredentialError>> {
        Box::pin(async move { unimplemented!("See docs/spec/interfaces/azure-adapter.md") })
    }
}
