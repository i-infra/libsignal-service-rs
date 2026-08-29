//! Profile key credential flow for Groups v2.
//!
//! Adding a user as a *full* member of a group requires proving to the groups
//! server that you know their profile key, without revealing it. That proof is
//! an [`ExpiringProfileKeyCredential`], issued by the chat server and presented
//! (blinded) to the groups server.
//!
//! The flow is:
//!
//! 1. Build a [`ProfileKeyCredentialRequestContext`] from the target's ACI and
//!    profile key. The context holds the blinding secrets; the derived
//!    *request* is what goes over the wire.
//! 2. `GET /v1/profile/{aci}/{version}/{request}` — the versioned profile
//!    endpoint, with the hex-encoded request appended. The response carries the
//!    usual profile fields plus a `credential`.
//! 3. Feed the response back through the context to unblind it into an
//!    [`ExpiringProfileKeyCredential`].
//!
//! Credentials are day-aligned and valid for at most 7 days; zkgroup rejects
//! anything outside that window at receive time, so callers must cache with
//! expiry and refetch rather than treating a stale credential as fatal.

use libsignal_protocol::Aci;
use reqwest::Method;
use serde::Deserialize;
use zkgroup::{
    profiles::{
        ExpiringProfileKeyCredential, ExpiringProfileKeyCredentialResponse,
        ProfileKey, ProfileKeyCredentialRequestContext,
    },
    ServerPublicParams,
};

use crate::{
    content::ServiceError,
    utils::serde_optional_base64,
    websocket::{self, profile::SignalServiceProfile, SignalWebSocket},
};

/// A versioned profile response that also carries a profile key credential.
///
/// This is the same JSON body as [`SignalServiceProfile`], plus the
/// `credential` field the server adds when the request path includes a
/// credential request. Java equivalent: `SignalServiceProfile` with
/// `ProfileKeyCredentialResponse`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalServiceProfileWithCredential {
    #[serde(flatten)]
    pub profile: SignalServiceProfile,

    /// Serialized [`ExpiringProfileKeyCredentialResponse`]. Absent if the
    /// server declined to issue one (e.g. the profile key version did not
    /// match the stored profile).
    #[serde(default, with = "serde_optional_base64")]
    pub credential: Option<Vec<u8>>,
}

/// Builds the request context for a profile key credential.
///
/// The returned context must be kept until the server response arrives — it
/// holds the blinding secrets needed to unblind the issued credential.
pub fn create_credential_request_context<R: rand::Rng + rand::CryptoRng>(
    server_public_params: &ServerPublicParams,
    aci: Aci,
    profile_key: ProfileKey,
    rng: &mut R,
) -> ProfileKeyCredentialRequestContext {
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);
    server_public_params.create_profile_key_credential_request_context(
        randomness,
        aci,
        profile_key,
    )
}

/// Unblinds a server credential response into a usable credential.
///
/// `current_time` is checked against the credential's expiration by zkgroup:
/// the credential must be day-aligned and expire within 7 days, otherwise this
/// returns [`ServiceError::GroupsV2Error`].
pub fn receive_credential(
    server_public_params: &ServerPublicParams,
    context: &ProfileKeyCredentialRequestContext,
    response_bytes: &[u8],
    current_time: std::time::SystemTime,
) -> Result<ExpiringProfileKeyCredential, ServiceError> {
    let response: ExpiringProfileKeyCredentialResponse =
        zkgroup::deserialize(response_bytes)
            .map_err(|_| ServiceError::GroupsV2Error)?;

    let now = current_time
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ServiceError::GroupsV2Error)?
        .as_secs();

    server_public_params
        .receive_expiring_profile_key_credential(
            context,
            &response,
            zkgroup::Timestamp::from_epoch_seconds(now),
        )
        .map_err(|_| ServiceError::GroupsV2Error)
}

/// An expiry-aware cache of profile key credentials, keyed by ACI.
///
/// Credentials are valid for at most 7 days and zkgroup refuses to *receive* an
/// expired one, so a stale entry must be dropped and refetched rather than
/// surfaced as an error. [`get`][Self::get] applies that policy: an entry
/// within `skew` of expiry is treated as absent.
#[derive(Default, Clone)]
pub struct ProfileKeyCredentialCache {
    entries: std::collections::HashMap<
        Aci,
        (ExpiringProfileKeyCredential, std::time::SystemTime),
    >,
}

// Manual: zkgroup's credential type is opaque and not Debug. Print only the
// cache shape — never credential material.
impl std::fmt::Debug for ProfileKeyCredentialCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileKeyCredentialCache")
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl ProfileKeyCredentialCache {
    /// Refetch a credential this close to its expiry rather than risk it
    /// lapsing mid-flight between the fetch and the groups-server call.
    const SKEW: std::time::Duration = std::time::Duration::from_secs(60 * 60);

    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a cached credential for `aci`, if one is present and not within
    /// [`SKEW`][Self::SKEW] of expiring at `now`.
    pub fn get(
        &self,
        aci: &Aci,
        now: std::time::SystemTime,
    ) -> Option<&ExpiringProfileKeyCredential> {
        let (credential, expiry) = self.entries.get(aci)?;
        (*expiry > now + Self::SKEW).then_some(credential)
    }

    pub fn insert(
        &mut self,
        aci: Aci,
        credential: ExpiringProfileKeyCredential,
    ) {
        let expiry = std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(
                credential.get_expiration_time().epoch_seconds(),
            );
        self.entries.insert(aci, (credential, expiry));
    }

    /// Drops entries that have expired as of `now`, ignoring skew.
    pub fn evict_expired(&mut self, now: std::time::SystemTime) {
        self.entries.retain(|_, (_, expiry)| *expiry > now);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl SignalWebSocket<websocket::Identified> {
    /// Fetches a versioned profile together with an expiring profile key
    /// credential.
    ///
    /// Java equivalent: `getProfile` with a `ProfileKeyCredentialRequest`.
    /// Returns the raw response; use [`receive_credential`] with the matching
    /// context to unblind it.
    pub async fn retrieve_profile_with_credential(
        &mut self,
        aci: Aci,
        profile_key: ProfileKey,
        request: &zkgroup::profiles::ProfileKeyCredentialRequest,
    ) -> Result<SignalServiceProfileWithCredential, ServiceError> {
        // Both the version and the request are transparently bincode-encoded
        // to hex strings, matching the path format the server expects.
        let version =
            bincode::serialize(&profile_key.get_profile_key_version(aci))?;
        let version = std::str::from_utf8(&version)
            .expect("profile key version is a hex encoded string");

        let request = hex::encode(zkgroup::serialize(request));

        let path = format!(
            "/v1/profile/{}/{}/{}?credentialType=expiringProfileKey",
            aci.service_id_string(),
            version,
            request,
        );

        self.http_request(Method::GET, path)?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
    }
}
