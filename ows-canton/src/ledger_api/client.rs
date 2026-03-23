//! HTTP JSON API client for the Canton Ledger API v2.
//!
//! Implements the `reqwest`-based client with authentication token injection,
//! retry logic (3x on connection error, 2x on 5xx), and error mapping from
//! HTTP status codes to [`CantonError`] variants.

use std::time::Duration;

use reqwest::StatusCode;

use crate::CantonError;

use super::types::*;

/// Default request timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum retries for connection errors (exponential backoff: 1s, 2s, 4s).
const MAX_CONN_RETRIES: u32 = 3;

/// Maximum retries for 5xx server errors (1s fixed delay).
const MAX_5XX_RETRIES: u32 = 2;

/// HTTP JSON API client for a Canton Participant Node.
#[derive(Debug, Clone)]
pub struct LedgerApiClient {
    http: reqwest::Client,
    base_url: String,
    auth_token: Option<String>,
    timeout: Duration,
}

impl LedgerApiClient {
    /// Create a new Ledger API client.
    pub fn new(base_url: &str, auth_token: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .expect("failed to build HTTP client");

        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Create a client with a custom timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("failed to build HTTP client");
        self
    }

    // ── Health ─────────────────────────────────────────────────────

    /// Check participant node health.
    ///
    /// Returns `true` if the node responds with HTTP 200.
    pub async fn health_check(&self) -> Result<bool, CantonError> {
        let url = format!("{}/health", self.base_url);
        match self.get_raw(&url).await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    // ── Synchronizers ──────────────────────────────────────────────

    /// Get connected synchronizers.
    pub async fn get_connected_synchronizers(
        &self,
    ) -> Result<Vec<ConnectedSynchronizer>, CantonError> {
        let url = format!("{}/v2/state/connected-synchronizers", self.base_url);
        let resp: ConnectedSynchronizersResponse = self.get_json(&url).await?;
        Ok(resp.connected_synchronizers)
    }

    // ── Party Management ───────────────────────────────────────────

    /// Generate topology transactions for an External Party.
    pub async fn generate_external_topology(
        &self,
        public_key_base64: &str,
        synchronizer: &str,
    ) -> Result<GenerateTopologyResponse, CantonError> {
        let url = format!("{}/v2/parties/external/generate-topology", self.base_url);
        let body = GenerateTopologyRequest {
            public_key: public_key_base64.to_string(),
            synchronizer: synchronizer.to_string(),
        };
        self.post_json(&url, &body).await
    }

    /// Allocate an External Party with signed topology transactions.
    pub async fn allocate_external_party(
        &self,
        req: &AllocatePartyRequest,
    ) -> Result<AllocatePartyResponse, CantonError> {
        let url = format!("{}/v2/parties/external/allocate", self.base_url);
        self.post_json(&url, req).await
    }

    /// List parties, optionally filtered.
    pub async fn list_parties(
        &self,
        filter: Option<&str>,
    ) -> Result<Vec<PartyDetails>, CantonError> {
        let mut url = format!("{}/v2/parties", self.base_url);
        if let Some(f) = filter {
            url.push_str(&format!("?filter-party={f}"));
        }
        let resp: PartiesResponse = self.get_json(&url).await?;
        Ok(resp.party_details)
    }

    // ── Command Submission ─────────────────────────────────────────

    /// Submit a signed command to the Ledger API.
    pub async fn submit_command(
        &self,
        req: &SubmitCommandRequest,
    ) -> Result<SubmitCommandResponse, CantonError> {
        let url = format!("{}/v2/commands/submit", self.base_url);
        self.post_json(&url, req).await
    }

    /// Simulate a command without committing.
    pub async fn simulate_command(
        &self,
        req: &SimulateCommandRequest,
    ) -> Result<SimulateCommandResponse, CantonError> {
        let url = format!("{}/v2/commands/simulate", self.base_url);
        self.post_json(&url, req).await
    }

    // ── Queries ────────────────────────────────────────────────────

    /// Get active contracts for a template and parties.
    pub async fn get_active_contracts(
        &self,
        template_id: &str,
        parties: &[String],
    ) -> Result<Vec<ActiveContract>, CantonError> {
        let parties_param = parties.join(",");
        let url = format!(
            "{}/v2/state/active-contracts?template-id={}&parties={}",
            self.base_url, template_id, parties_param
        );
        let resp: ActiveContractsResponse = self.get_json(&url).await?;
        Ok(resp.active_contracts)
    }

    /// Get command completions after a given offset.
    pub async fn get_completions(
        &self,
        offset: &str,
        parties: &[String],
    ) -> Result<Vec<Completion>, CantonError> {
        let parties_param = parties.join(",");
        let url = format!(
            "{}/v2/completions?offset={}&parties={}",
            self.base_url, offset, parties_param
        );
        let resp: CompletionsResponse = self.get_json(&url).await?;
        Ok(resp.completions)
    }

    // ── Internal HTTP helpers ──────────────────────────────────────

    /// Send a GET request and return the raw response (no retry).
    async fn get_raw(&self, url: &str) -> Result<reqwest::Response, CantonError> {
        let mut req = self.http.get(url);
        if let Some(token) = &self.auth_token {
            req = req.bearer_auth(token);
        }
        req.send().await.map_err(|e| map_reqwest_error(&e))
    }

    /// Send a GET request, parse JSON response, with retry.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, CantonError> {
        let resp = self
            .execute_with_retry(|| {
                let mut req = self.http.get(url);
                if let Some(token) = &self.auth_token {
                    req = req.bearer_auth(token);
                }
                req
            })
            .await?;

        let body = resp
            .text()
            .await
            .map_err(|e| CantonError::InvalidApiResponse {
                reason: e.to_string(),
            })?;

        serde_json::from_str(&body).map_err(|e| CantonError::InvalidApiResponse {
            reason: format!("JSON parse error: {e} — body: {}", truncate(&body, 200)),
        })
    }

    /// Send a POST request with JSON body, parse JSON response, with retry.
    async fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T, CantonError> {
        let resp = self
            .execute_with_retry(|| {
                let mut req = self.http.post(url).json(body);
                if let Some(token) = &self.auth_token {
                    req = req.bearer_auth(token);
                }
                req
            })
            .await?;

        let response_body = resp
            .text()
            .await
            .map_err(|e| CantonError::InvalidApiResponse {
                reason: e.to_string(),
            })?;

        serde_json::from_str(&response_body).map_err(|e| CantonError::InvalidApiResponse {
            reason: format!(
                "JSON parse error: {e} — body: {}",
                truncate(&response_body, 200)
            ),
        })
    }

    /// Execute a request builder with retry logic.
    ///
    /// - Connection errors: up to 3 retries with exponential backoff (1s, 2s, 4s).
    /// - 5xx errors: up to 2 retries with 1s fixed delay.
    /// - 4xx errors: no retry.
    async fn execute_with_retry<F>(
        &self,
        build_request: F,
    ) -> Result<reqwest::Response, CantonError>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        let mut conn_retries = 0u32;
        let mut server_retries = 0u32;

        loop {
            let result = build_request().send().await;

            match result {
                Ok(resp) => {
                    let status = resp.status();

                    if status.is_success() {
                        return Ok(resp);
                    }

                    // 5xx — retry with fixed delay.
                    if status.is_server_error() && server_retries < MAX_5XX_RETRIES {
                        server_retries += 1;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }

                    // Map HTTP error status to CantonError.
                    let body = resp.text().await.unwrap_or_default();
                    return Err(map_http_error(status, &body));
                }
                Err(e) => {
                    if e.is_timeout() {
                        return Err(CantonError::RequestTimeout {
                            ms: self.timeout.as_millis() as u64,
                        });
                    }

                    // Connection error — retry with exponential backoff.
                    if conn_retries < MAX_CONN_RETRIES {
                        let delay = Duration::from_secs(1 << conn_retries);
                        conn_retries += 1;
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    return Err(map_reqwest_error(&e));
                }
            }
        }
    }
}

/// Map an HTTP error status code to a `CantonError`.
fn map_http_error(status: StatusCode, body: &str) -> CantonError {
    match status.as_u16() {
        401 => CantonError::Unauthorized,
        403 => CantonError::Forbidden {
            reason: body.to_string(),
        },
        404 => CantonError::InvalidApiResponse {
            reason: format!("not found: {body}"),
        },
        409 => CantonError::OnboardingFailed {
            reason: format!("conflict: {body}"),
        },
        s if (500..600).contains(&s) => CantonError::ServerError {
            status: s,
            body: body.to_string(),
        },
        _ => CantonError::InvalidApiResponse {
            reason: format!("HTTP {status}: {body}"),
        },
    }
}

/// Map a reqwest transport error to a `CantonError`.
fn map_reqwest_error(e: &reqwest::Error) -> CantonError {
    if e.is_timeout() {
        CantonError::RequestTimeout { ms: 0 }
    } else {
        CantonError::ConnectionFailed {
            reason: e.to_string(),
        }
    }
}

/// Truncate a string for error messages.
fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        &s[..max_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ── Health check ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_health_check_ok() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        assert!(client.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn test_health_check_fail() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        // health_check returns false on error, not Err.
        assert!(!client.health_check().await.unwrap());
    }

    // ── Generate topology ──────────────────────────────────────────

    #[tokio::test]
    async fn test_generate_topology_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/parties/external/generate-topology"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyId": "alice::1220abcd",
                "transactions": ["dHgx", "dHgy"]
            })))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let resp = client
            .generate_external_topology("MCowBQ...", "canton::sync1")
            .await
            .unwrap();
        assert_eq!(resp.party_id, "alice::1220abcd");
        assert_eq!(resp.transactions.len(), 2);
    }

    #[tokio::test]
    async fn test_generate_topology_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/parties/external/generate-topology"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let err = client
            .generate_external_topology("bad-key", "canton::sync1")
            .await
            .unwrap_err();
        assert!(matches!(err, CantonError::InvalidApiResponse { .. }));
    }

    // ── Allocate party ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_allocate_party_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/parties/external/allocate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyId": "alice::1220abcd"
            })))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let req = AllocatePartyRequest {
            synchronizer: "canton::sync1".to_string(),
            onboarding_transactions: vec!["dHgx".to_string()],
            multi_hash_signatures: vec![MultiHashSignatureRequest {
                format: "SIGNATURE_FORMAT_CONCAT".to_string(),
                signature: "c2ln".to_string(),
                signed_by: "1220abcd".to_string(),
                signing_algorithm_spec: "SIGNING_ALGORITHM_SPEC_ED25519".to_string(),
            }],
        };
        let resp = client.allocate_external_party(&req).await.unwrap();
        assert_eq!(resp.party_id, "alice::1220abcd");
    }

    #[tokio::test]
    async fn test_allocate_party_conflict() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/parties/external/allocate"))
            .respond_with(ResponseTemplate::new(409).set_body_string("party already exists"))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let req = AllocatePartyRequest {
            synchronizer: "canton::sync1".to_string(),
            onboarding_transactions: vec![],
            multi_hash_signatures: vec![],
        };
        let err = client.allocate_external_party(&req).await.unwrap_err();
        assert!(matches!(err, CantonError::OnboardingFailed { .. }));
    }

    // ── List parties ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_parties() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/parties"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyDetails": [
                    { "party": "alice::1220abcd", "isLocal": false, "participantPermissions": [] },
                    { "party": "bob::1220ffff", "isLocal": true, "participantPermissions": [] }
                ]
            })))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let parties = client.list_parties(None).await.unwrap();
        assert_eq!(parties.len(), 2);
        assert_eq!(parties[0].party, "alice::1220abcd");
        assert!(!parties[0].is_local);
        assert!(parties[1].is_local);
    }

    // ── Submit command ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_submit_command_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/commands/submit"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "commandId": "cmd-001",
                "completionOffset": "42",
                "transactionId": "tx-abc"
            })))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let req = SubmitCommandRequest {
            commands: serde_json::json!({"commandId": "cmd-001"}),
            multi_hash_signatures: vec![],
        };
        let resp = client.submit_command(&req).await.unwrap();
        assert_eq!(resp.command_id, "cmd-001");
        assert_eq!(resp.transaction_id.as_deref(), Some("tx-abc"));
    }

    // ── Simulate command ───────────────────────────────────────────

    #[tokio::test]
    async fn test_simulate_command_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/commands/simulate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let req = SimulateCommandRequest {
            commands: serde_json::json!({}),
        };
        let resp = client.simulate_command(&req).await.unwrap();
        assert!(resp.success);
    }

    // ── Auth header ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_auth_header_included() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/parties"))
            .and(header("Authorization", "Bearer my-jwt-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyDetails": []
            })))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), Some("my-jwt-token".to_string()));
        let parties = client.list_parties(None).await.unwrap();
        assert!(parties.is_empty());
    }

    #[tokio::test]
    async fn test_auth_header_absent() {
        let mock = MockServer::start().await;
        // This mock ONLY matches when Authorization header is absent.
        Mock::given(method("GET"))
            .and(path("/v2/parties"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyDetails": []
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        client.list_parties(None).await.unwrap();
    }

    // ── Timeout ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_timeout() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/parties"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"partyDetails": []}))
                    .set_delay(Duration::from_secs(5)),
            )
            .mount(&mock)
            .await;

        let client =
            LedgerApiClient::new(&mock.uri(), None).with_timeout(Duration::from_millis(100));
        let err = client.list_parties(None).await.unwrap_err();
        assert!(matches!(err, CantonError::RequestTimeout { .. }));
    }

    // ── Retry on 5xx ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_retry_on_5xx() {
        let mock = MockServer::start().await;

        // First call returns 500, second returns 200.
        Mock::given(method("GET"))
            .and(path("/v2/parties"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path("/v2/parties"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partyDetails": [{"party": "ok::12345678", "isLocal": false}]
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let parties = client.list_parties(None).await.unwrap();
        assert_eq!(parties.len(), 1);
        assert_eq!(parties[0].party, "ok::12345678");
    }

    // ── HTTP error mapping ─────────────────────────────────────────

    #[tokio::test]
    async fn test_unauthorized() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/parties"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock)
            .await;

        let client = LedgerApiClient::new(&mock.uri(), None);
        let err = client.list_parties(None).await.unwrap_err();
        assert!(matches!(err, CantonError::Unauthorized));
    }
}
