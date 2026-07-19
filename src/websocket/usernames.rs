use crate::utils::serde_base64_url_safe_no_pad;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use libsignal_core::{Aci, ServiceIdKind};
use reqwest::Method;
use serde::Serialize;

use crate::content::ServiceError;

use super::{Identified, SignalWebSocket, Unidentified};

impl SignalWebSocket<Unidentified> {
    pub async fn look_up_username(
        &mut self,
        username: &usernames::Username,
    ) -> Result<Option<Aci>, ServiceError> {
        self.look_up_username_hash(&username.hash()).await
    }

    // Based on libsignal-net
    pub async fn look_up_username_hash(
        &mut self,
        hash: &[u8],
    ) -> Result<Option<Aci>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameHashResponse {
            uuid: String,
        }

        let response = self
            .http_request(
                Method::GET,
                format!(
                    "/v1/accounts/username_hash/{}",
                    BASE64_URL_SAFE_NO_PAD.encode(hash)
                ),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username not found");
            return Ok(None);
        }

        let result: UsernameHashResponse =
            response.service_error_for_status().await?.json().await?;

        Ok(Some(
            Aci::parse_from_service_id_string(&result.uuid).ok_or_else(
                || ServiceError::InvalidAddressType(ServiceIdKind::Aci),
            )?,
        ))
    }

    /// Looks up the encrypted username stored at a username link handle and
    /// decrypts it.
    ///
    /// `link` must be a full `https://signal.me/#eu/<payload>` URL. The payload
    /// is the URL-safe base64 encoding of the 32-byte link entropy followed by
    /// the 16-byte link handle UUID.
    // Based on libsignal-net
    pub async fn look_up_username_link(
        &mut self,
        link: &url::Url,
    ) -> Result<Option<usernames::Username>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameLinkResponse {
            #[serde(rename = "usernameLinkEncryptedValue")]
            #[serde(with = "serde_base64_url_safe_no_pad")]
            encrypted_username: Vec<u8>,
        }

        let (uuid, entropy) = parse_username_link(link)?;

        let response = self
            .http_request(
                Method::GET,
                format!("/v1/accounts/username_link/{uuid}"),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username link not found");
            return Ok(None);
        }

        let result: UsernameLinkResponse =
            response.service_error_for_status().await?.json().await?;

        let plaintext_username =
            usernames::decrypt_username(&entropy, &result.encrypted_username)
                .map_err(|error| {
                tracing::error!(%error, "undecryptable username");
                ServiceError::InvalidFrame {
                    reason: "undecryptable username link",
                }
            })?;

        let validated_username = usernames::Username::new(&plaintext_username).map_err(|e| {
            // Exhaustively match UsernameError to make sure there's nothing we shouldn't log.
            #[allow(clippy::let_unit_value)]
            let _username_error_carries_no_information_that_would_be_bad_to_log = match e {
                usernames::UsernameError::MissingSeparator
                | usernames::UsernameError::NicknameCannotBeEmpty
                | usernames::UsernameError::NicknameCannotStartWithDigit
                | usernames::UsernameError::BadNicknameCharacter
                | usernames::UsernameError::NicknameTooShort
                | usernames::UsernameError::NicknameTooLong
                | usernames::UsernameError::DiscriminatorCannotBeEmpty
                | usernames::UsernameError::DiscriminatorCannotBeZero
                | usernames::UsernameError::DiscriminatorCannotBeSingleDigit
                | usernames::UsernameError::DiscriminatorCannotHaveLeadingZeros
                | usernames::UsernameError::BadDiscriminatorCharacter
                | usernames::UsernameError::DiscriminatorTooLarge => {}
            };
            tracing::warn!(error=%e, "username link decrypted to an invalid username");
            tracing::debug!(error=%e,
                "username link decrypted to '{plaintext_username}', which is not valid"
            );
            // The user didn't ever type this username, so the precise way in which it's invalid
            // isn't important. Treat this equivalent to having found garbage data in the link. This
            // simplifies error handling for callers.
            ServiceError::InvalidFrame {
                reason: "undecryptable username link",
            }
        })?;

        Ok(Some(validated_username))
    }
}

/// Splits a username link into its link handle UUID and link entropy.
///
/// `link` must be a full `https://signal.me/#eu/<payload>` URL. The payload is
/// URL-safe base64 (no padding) of the 32-byte entropy followed by the 16-byte
/// handle UUID.
fn parse_username_link(
    link: &url::Url,
) -> Result<
    (
        uuid::Uuid,
        [u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ),
    ServiceError,
> {
    if link.scheme() != "https" || link.host_str() != Some("signal.me") {
        return Err(ServiceError::InvalidFrame {
            reason: "username link base is not https://signal.me",
        });
    }

    let fragment =
        link.fragment().ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link missing fragment",
        })?;
    let mut segments = fragment.split('/');
    if segments.next() != Some("eu") {
        return Err(ServiceError::InvalidFrame {
            reason: "username link must start with #eu/",
        });
    }
    let payload =
        segments.next().ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link payload missing",
        })?;
    if segments.next().is_some() {
        return Err(ServiceError::InvalidFrame {
            reason: "username link has extra path segments",
        });
    }

    let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload)?;

    let (entropy, rest) = bytes
        .split_first_chunk::<{ usernames::constants::USERNAME_LINK_ENTROPY_SIZE }>()
        .ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link payload shorter than entropy",
        })?;

    let handle_uuid = uuid::Uuid::from_slice(rest).map_err(|_| {
        ServiceError::InvalidFrame {
            reason: "username link payload missing handle UUID",
        }
    })?;

    Ok((handle_uuid, *entropy))
}

/// A confirmed username: the account's new username, its server-assigned
/// link handle, and the link entropy needed to reconstruct the shareable
/// URL (via [`generate_username_link`]).
pub struct ConfirmedUsername {
    pub username: usernames::Username,
    pub link_handle: uuid::Uuid,
    pub link_entropy: [u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
}

impl ConfirmedUsername {
    pub fn link(&self) -> url::Url {
        generate_username_link(self.link_handle, &self.link_entropy)
    }
}

impl SignalWebSocket<Identified> {
    /// Reserves one of the candidate usernames and returns the index of the
    /// winning candidate.
    ///
    /// The reservation is tentative until [`Self::confirm_username`] is
    /// called. Server: HTTP 409 when every candidate is taken, 429 when
    /// rate-limited.
    ///
    /// Java equivalent: `AccountApi.reserveUsername`
    pub async fn reserve_username(
        &mut self,
        candidates: &[usernames::Username],
    ) -> Result<usize, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ReserveUsernameRequest {
            username_hashes: Vec<String>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ReserveUsernameResponse {
            #[serde(with = "serde_base64_url_safe_no_pad")]
            username_hash: Vec<u8>,
        }

        let hashes: Vec<[u8; 32]> =
            candidates.iter().map(|c| c.hash()).collect();
        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_hash/reserve")?
            .send_json(ReserveUsernameRequest {
                username_hashes: hashes
                    .iter()
                    .map(|hash| BASE64_URL_SAFE_NO_PAD.encode(hash))
                    .collect(),
            })
            .await?
            .service_error_for_status()
            .await?;
        let result: ReserveUsernameResponse = response.json().await?;

        hashes
            .iter()
            .position(|hash| hash[..] == result.username_hash[..])
            .ok_or(ServiceError::InvalidFrame {
                reason: "server reserved a hash we did not offer",
            })
    }

    /// Confirms a username previously reserved with
    /// [`Self::reserve_username`], simultaneously establishing its username
    /// link (the `encryptedUsername` sent along is the link blob).
    ///
    /// Server: HTTP 409 when the reservation is missing or does not match,
    /// 410 when the username has become unavailable, 429 when rate-limited.
    ///
    /// Java equivalent: `AccountApi.confirmUsername`
    pub async fn confirm_username(
        &mut self,
        username: usernames::Username,
        link_entropy: Option<
            &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
        >,
    ) -> Result<ConfirmedUsername, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ConfirmUsernameRequest {
            #[serde(with = "serde_base64_url_safe_no_pad")]
            username_hash: Vec<u8>,
            #[serde(with = "serde_base64_url_safe_no_pad")]
            zk_proof: Vec<u8>,
            #[serde(with = "serde_base64_url_safe_no_pad")]
            encrypted_username: Vec<u8>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ConfirmUsernameResponse {
            username_link_handle: uuid::Uuid,
        }

        let mut rng = rand::rng();
        let randomness: [u8; 32] = rand::Rng::random(&mut rng);
        let proof = username.proof(&randomness).map_err(|error| {
            tracing::error!(%error, "failed to generate username proof");
            ServiceError::InvalidFrame {
                reason: "failed to generate username proof",
            }
        })?;
        // Passing the previous link entropy back in reclaims the existing
        // link URL; `None` mints a fresh link.
        let (entropy, ciphertext) = usernames::create_for_username(
            &mut rng,
            username.to_string(),
            link_entropy,
        )
        .map_err(|_e| ServiceError::InvalidFrame {
            reason: "username too long to encrypt",
        })?;

        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_hash/confirm")?
            .send_json(ConfirmUsernameRequest {
                username_hash: username.hash().to_vec(),
                zk_proof: proof,
                encrypted_username: ciphertext,
            })
            .await?
            .service_error_for_status()
            .await?;
        let result: ConfirmUsernameResponse = response.json().await?;

        Ok(ConfirmedUsername {
            username,
            link_handle: result.username_link_handle,
            link_entropy: entropy,
        })
    }

    /// Clears the account's username (and thereby its username link).
    ///
    /// Java equivalent: `AccountApi.deleteUsername`
    pub async fn delete_username(&mut self) -> Result<(), ServiceError> {
        self.http_request(Method::DELETE, "/v1/accounts/username_hash")?
            .send()
            .await?
            .service_error_for_status()
            .await?;
        Ok(())
    }

    /// Deletes the account's username link (the username itself remains).
    pub async fn delete_username_link(&mut self) -> Result<(), ServiceError> {
        self.http_request(Method::DELETE, "/v1/accounts/username_link")?
            .send()
            .await?
            .service_error_for_status()
            .await?;
        Ok(())
    }

    /// Sets the account's username link to encrypt `username` and returns the
    /// shareable `https://signal.me/#eu/...` link.
    ///
    /// Generates fresh entropy and, unless `keep_link_handle` is `true` and the
    /// account already has a link handle, a fresh server-assigned handle.
    // Based on libsignal-net
    pub async fn set_username_link(
        &mut self,
        username: &usernames::Username,
        keep_link_handle: bool,
    ) -> Result<url::Url, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SetUsernameLinkRequest {
            #[serde(with = "serde_base64_url_safe_no_pad")]
            username_link_encrypted_value: Vec<u8>,
            keep_link_handle: bool,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct UsernameLinkHandleResponse {
            username_link_handle: uuid::Uuid,
        }

        let (entropy, ciphertext) = usernames::create_for_username(
            &mut rand::rng(),
            username.to_string(),
            None,
        )
        .map_err(|_e| ServiceError::InvalidFrame {
            reason: "username too long to encrypt",
        })?;

        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_link")?
            .send_json(SetUsernameLinkRequest {
                username_link_encrypted_value: ciphertext,
                keep_link_handle,
            })
            .await?
            .service_error_for_status()
            .await?;

        let result: UsernameLinkHandleResponse = response.json().await?;

        Ok(generate_username_link(
            result.username_link_handle,
            &entropy,
        ))
    }
}

/// Builds the `https://signal.me/#eu/<base64url>` link from its parts.
///
/// `entropy` is the 32-byte link entropy; `handle` is the server-assigned
/// link handle UUID. The payload is the URL-safe base64 (no padding) of
/// `entropy || handle`.
pub fn generate_username_link(
    handle: uuid::Uuid,
    entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
) -> url::Url {
    let mut payload = entropy.to_vec();
    payload.extend_from_slice(handle.as_bytes());
    let mut result = String::from("https://signal.me/#eu/");
    BASE64_URL_SAFE_NO_PAD.encode_string(&payload, &mut result);

    url::Url::parse(&result).expect("can only generate valid URLs")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generate_and_parse_link_round_trip() {
        let entropy = [0x42; usernames::constants::USERNAME_LINK_ENTROPY_SIZE];
        let handle = uuid::uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
        // deliberately chosen to round-trip cleanly through URL-safe base64
        let link = generate_username_link(handle, &entropy);
        assert!(link.as_str().starts_with("https://signal.me/#eu/"));

        let (parsed_handle, parsed_entropy) =
            parse_username_link(&link).unwrap();
        assert_eq!(parsed_handle, handle);
        assert_eq!(parsed_entropy, entropy);
    }

    #[test]
    fn parse_link_rejects_wrong_base() {
        let entropy = [0x42; usernames::constants::USERNAME_LINK_ENTROPY_SIZE];
        let handle = uuid::uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
        let bad_link = generate_username_link(handle, &entropy)
            .to_string()
            .replace("signal.me", "example.com");
        let bad_link = url::Url::parse(&bad_link).unwrap();
        assert!(parse_username_link(&bad_link).is_err());
    }

    #[test]
    fn parse_link_rejects_missing_eu_marker() {
        let bad_link = url::Url::parse(
            "https://signal.me/#foo/R_rHg5IQLE60Qad5l8rV-6x2TMcVnDYvOV-igYXJj6GK1NuNeE9LKI3V_VZ8IH2p",
        )
        .unwrap();
        assert!(parse_username_link(&bad_link).is_err());
    }

    #[test]
    fn parse_link_rejects_extra_fragment_segments() {
        let bad_link =
            url::Url::parse("https://signal.me/#eu/payload/extra").unwrap();
        assert!(parse_username_link(&bad_link).is_err());
    }
}
