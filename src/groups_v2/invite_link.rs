//! Group invite links: `https://signal.group/#<base64url(GroupInviteLink)>`.
//!
//! The fragment carries the group master key and the current invite-link
//! password. Anyone holding the link can therefore read the group's join
//! info; the password (not the key alone) is what the server checks when
//! they try to join, so rotating the password invalidates old links.

use base64::prelude::*;
use prost::Message;
use zkgroup::GROUP_MASTER_KEY_LEN;

use crate::proto::{group_invite_link, GroupInviteLink as ProtoInviteLink};

/// Length of the password Signal's clients generate for a new link.
pub const INVITE_LINK_PASSWORD_LEN: usize = 16;

const HOST: &str = "signal.group";

#[derive(Debug, thiserror::Error)]
pub enum InviteLinkError {
    #[error("not a signal.group invite link")]
    NotAnInviteLink,
    #[error("invite link fragment is not valid base64url: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invite link contents could not be decoded: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invite link is of an unsupported version")]
    UnsupportedVersion,
    #[error("invite link carries a master key of the wrong length")]
    WrongMasterKeyLength,
}

/// The decoded contents of an invite link.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupInviteLink {
    pub master_key: [u8; GROUP_MASTER_KEY_LEN],
    pub password: Vec<u8>,
}

impl std::fmt::Debug for GroupInviteLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Both fields are secrets: the key lets anyone read the group.
        f.debug_struct("GroupInviteLink").finish_non_exhaustive()
    }
}

impl GroupInviteLink {
    /// Generates a fresh random password of the standard length.
    pub fn generate_password<R: rand::Rng + rand::CryptoRng>(
        rng: &mut R,
    ) -> Vec<u8> {
        let mut password = vec![0u8; INVITE_LINK_PASSWORD_LEN];
        rng.fill_bytes(&mut password);
        password
    }

    /// The password as it appears in groups-server paths and queries.
    pub fn encode_password(password: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(password)
    }

    /// Renders the shareable `https://signal.group/#…` URL.
    pub fn to_url(&self) -> String {
        let contents = ProtoInviteLink {
            contents: Some(group_invite_link::Contents::ContentsV1(
                group_invite_link::GroupInviteLinkContentsV1 {
                    group_master_key: self.master_key.to_vec(),
                    invite_link_password: self.password.clone(),
                },
            )),
        }
        .encode_to_vec();
        format!(
            "https://{HOST}/#{}",
            BASE64_URL_SAFE_NO_PAD.encode(contents)
        )
    }

    /// Parses an `https://signal.group/#…` or `sgnl://signal.group/#…` URL.
    pub fn parse(url: &str) -> Result<Self, InviteLinkError> {
        let url = url.trim();
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("sgnl://"))
            .ok_or(InviteLinkError::NotAnInviteLink)?;
        let fragment = rest
            .strip_prefix(HOST)
            .and_then(|r| r.strip_prefix("/#"))
            .ok_or(InviteLinkError::NotAnInviteLink)?;
        Self::from_fragment(fragment)
    }

    fn from_fragment(fragment: &str) -> Result<Self, InviteLinkError> {
        // Be lenient about padding: Android emits none, but a link pasted
        // through a tool that "fixes" base64 may have gained some.
        let bytes =
            BASE64_URL_SAFE_NO_PAD.decode(fragment.trim_end_matches('='))?;
        let decoded = ProtoInviteLink::decode(bytes.as_slice())?;
        let Some(group_invite_link::Contents::ContentsV1(v1)) =
            decoded.contents
        else {
            return Err(InviteLinkError::UnsupportedVersion);
        };
        let master_key = v1
            .group_master_key
            .try_into()
            .map_err(|_| InviteLinkError::WrongMasterKeyLength)?;
        Ok(Self {
            master_key,
            password: v1.invite_link_password,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link() -> GroupInviteLink {
        GroupInviteLink {
            master_key: [7u8; GROUP_MASTER_KEY_LEN],
            password: (0..16).collect(),
        }
    }

    #[test]
    fn url_round_trips() {
        let url = link().to_url();
        assert!(url.starts_with("https://signal.group/#"));
        assert!(!url.contains('='), "no padding: {url}");
        assert_eq!(GroupInviteLink::parse(&url).unwrap(), link());
    }

    #[test]
    fn sgnl_scheme_and_padding_are_accepted() {
        let url = link().to_url();
        let padded = format!("{url}==");
        assert_eq!(GroupInviteLink::parse(&padded).unwrap(), link());
        let sgnl = url.replacen("https://", "sgnl://", 1);
        assert_eq!(GroupInviteLink::parse(&sgnl).unwrap(), link());
    }

    #[test]
    fn foreign_urls_are_rejected() {
        assert!(matches!(
            GroupInviteLink::parse("https://example.com/#abc"),
            Err(InviteLinkError::NotAnInviteLink)
        ));
        assert!(matches!(
            GroupInviteLink::parse("https://signal.group/#!!!"),
            Err(InviteLinkError::Base64(_))
        ));
    }

    #[test]
    fn generated_password_has_standard_length_and_is_random() {
        let mut rng = rand::rng();
        let a = GroupInviteLink::generate_password(&mut rng);
        let b = GroupInviteLink::generate_password(&mut rng);
        assert_eq!(a.len(), INVITE_LINK_PASSWORD_LEN);
        assert_ne!(a, b);
    }

    #[test]
    fn debug_never_prints_secrets() {
        let text = format!("{:?}", link());
        assert!(!text.contains("7, 7"));
        assert!(!text.contains("password"));
    }
}
