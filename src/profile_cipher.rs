use std::convert::TryInto;

use aes_gcm::{aead::Aead, AeadInOut, Aes256Gcm, KeyInit};
use libsignal_protocol::IdentityKey;
use prost::Message;
use rand::{CryptoRng, RngCore};
use zkgroup::profiles::ProfileKey;

use crate::{
    profile_name::ProfileName, websocket::profile::SignalServiceProfile,
    Profile,
};

/// Encrypt and decrypt a [`ProfileName`] and other profile information.
///
/// # Example
///
/// ```rust
/// # use libsignal_service::{profile_name::ProfileName, profile_cipher::ProfileCipher};
/// # use zkgroup::profiles::ProfileKey;
/// # use rand::Rng;
/// # let mut rng = rand::rng();
/// # let some_randomness = rng.random();
/// let profile_key = ProfileKey::generate(some_randomness);
/// let name = ProfileName::<&str> {
///     given_name: "Bill",
///     family_name: None,
/// };
/// let cipher = ProfileCipher::new(profile_key);
/// let encrypted = cipher.encrypt_name(&name, &mut rng).unwrap();
/// let decrypted = cipher.decrypt_name(&encrypted).unwrap().unwrap();
/// assert_eq!(decrypted.as_ref(), name);
/// ```
pub struct ProfileCipher {
    profile_key: ProfileKey,
}

const NAME_PADDED_LENGTH_1: usize = 53;
const NAME_PADDED_LENGTH_2: usize = 257;
const NAME_PADDING_BRACKETS: &[usize] =
    &[NAME_PADDED_LENGTH_1, NAME_PADDED_LENGTH_2];

const ABOUT_PADDED_LENGTH_1: usize = 128;
const ABOUT_PADDED_LENGTH_2: usize = 254;
const ABOUT_PADDED_LENGTH_3: usize = 512;
const ABOUT_PADDING_BRACKETS: &[usize] = &[
    ABOUT_PADDED_LENGTH_1,
    ABOUT_PADDED_LENGTH_2,
    ABOUT_PADDED_LENGTH_3,
];

const EMOJI_PADDED_LENGTH: usize = 32;

// Java: ProfileCipher.PAYMENTS_ADDRESS_CONTENT_SIZE.  The address is padded
// so its base64 representation occupies a fixed 776-char field; subtract the
// 28 bytes of AES-GCM overhead (12-byte nonce + 16-byte tag).
const PAYMENT_ADDRESS_ENCRYPTION_OVERHEAD: usize = 28;
const PAYMENT_ADDRESS_BASE64_FIELD_SIZE: usize = 776;
const PAYMENT_ADDRESS_CONTENT_SIZE: usize =
    PAYMENT_ADDRESS_BASE64_FIELD_SIZE * 6 / 8
        - PAYMENT_ADDRESS_ENCRYPTION_OVERHEAD;

#[derive(thiserror::Error, Debug)]
pub enum ProfileCipherError {
    #[error("Encryption error")]
    EncryptionError,
    #[error("UTF-8 decode error {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("Input name too long")]
    InputTooLong,
    #[error("Ciphertext too short")]
    CiphertextTooShort,
    #[error("Protobuf decode error {0}")]
    ProtobufError(#[from] prost::DecodeError),
}

/// A payment address is only trustworthy if its signature over the raw
/// MobileCoin address verifies against the profile owner's identity key.
///
/// Java: `PaymentUtils.verifyPaymentsAddress`.
fn verify_payment_address_signature(
    payment_address: &crate::proto::PaymentAddress,
    identity_key: Option<&[u8]>,
) -> bool {
    use crate::proto::payment_address::Address;

    let Some(identity_key) =
        identity_key.and_then(|bytes| IdentityKey::decode(bytes).ok())
    else {
        return false;
    };
    match &payment_address.address {
        Some(Address::MobileCoin(mobile_coin)) => {
            let (Some(address), Some(signature)) =
                (&mobile_coin.public_address, &mobile_coin.signature)
            else {
                return false;
            };
            identity_key
                .public_key()
                .verify_signature(address, signature)
        },
        None => false,
    }
}

fn pad_plaintext(
    bytes: &mut Vec<u8>,
    brackets: &[usize],
) -> Result<usize, ProfileCipherError> {
    let len = brackets
        .iter()
        .find(|x| **x >= bytes.len())
        .ok_or(ProfileCipherError::InputTooLong)?;
    let len: usize = *len;

    bytes.resize(len, 0);
    assert!(brackets.contains(&bytes.len()));

    Ok(len)
}

impl ProfileCipher {
    pub fn new(profile_key: ProfileKey) -> Self {
        Self { profile_key }
    }

    pub fn into_inner(self) -> ProfileKey {
        self.profile_key
    }

    fn pad_and_encrypt<R: RngCore + CryptoRng>(
        &self,
        mut bytes: Vec<u8>,
        padding_brackets: &[usize],
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let _len = pad_plaintext(&mut bytes, padding_brackets)?;
        self.encrypt_raw(bytes, csprng)
    }

    /// Java: `ProfileCipher::encryptWithLength` — the plaintext is prefixed
    /// with its length as a 4-byte little-endian integer before padding, so
    /// binary content survives zero-padding.
    fn pad_and_encrypt_with_length<R: RngCore + CryptoRng>(
        &self,
        bytes: &[u8],
        padding_brackets: &[usize],
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let len: i32 = bytes
            .len()
            .try_into()
            .map_err(|_| ProfileCipherError::InputTooLong)?;
        let mut prefixed = Vec::with_capacity(4 + bytes.len());
        prefixed.extend_from_slice(&len.to_le_bytes());
        prefixed.extend_from_slice(bytes);
        self.pad_and_encrypt(prefixed, padding_brackets, csprng)
    }

    /// AES-256-GCM without padding: `nonce (12) || ciphertext || tag (16)`.
    fn encrypt_raw<R: RngCore + CryptoRng>(
        &self,
        mut bytes: Vec<u8>,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let cipher = Aes256Gcm::new(&self.profile_key.get_bytes().into());
        let mut nonce = [0u8; 12];
        csprng.fill_bytes(&mut nonce);

        cipher
            .encrypt_in_place(&nonce.into(), b"", &mut bytes)
            .map_err(|_| ProfileCipherError::EncryptionError)?;

        let mut concat = Vec::with_capacity(nonce.len() + bytes.len());
        concat.extend_from_slice(&nonce);
        concat.extend_from_slice(&bytes);
        Ok(concat)
    }

    fn decrypt_raw(&self, bytes: &[u8]) -> Result<Vec<u8>, ProfileCipherError> {
        if bytes.len() < 12 + 16 {
            return Err(ProfileCipherError::CiphertextTooShort);
        }
        let nonce: [u8; 12] = bytes[0..12]
            .try_into()
            .expect("fixed length nonce material");
        let cipher = Aes256Gcm::new(&self.profile_key.get_bytes().into());
        cipher
            .decrypt(&nonce.into(), &bytes[12..])
            .map_err(|_| ProfileCipherError::EncryptionError)
    }

    /// Inverse of [`Self::pad_and_encrypt_with_length`].
    fn decrypt_with_length(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let mut plaintext = self.decrypt_raw(bytes)?;
        if plaintext.len() < 4 {
            return Err(ProfileCipherError::CiphertextTooShort);
        }
        let len = i32::from_le_bytes(
            plaintext[0..4].try_into().expect("4 length bytes"),
        );
        let len: usize = len
            .try_into()
            .map_err(|_| ProfileCipherError::CiphertextTooShort)?;
        if plaintext.len() < 4 + len {
            return Err(ProfileCipherError::CiphertextTooShort);
        }
        plaintext.drain(0..4);
        plaintext.truncate(len);
        Ok(plaintext)
    }

    fn decrypt_and_unpad(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let mut plaintext = self.decrypt_raw(bytes.as_ref())?;

        // Unpad
        let len = plaintext
            .iter()
            // Search the first non-0 char...
            .rposition(|x| *x != 0)
            // ...and strip until right after.
            .map(|x| x + 1)
            // If it's all zeroes, the string is 0-length.
            .unwrap_or(0);
        plaintext.truncate(len);
        Ok(plaintext)
    }

    pub fn decrypt(
        &self,
        encrypted_profile: SignalServiceProfile,
    ) -> Result<Profile, ProfileCipherError> {
        let name = encrypted_profile
            .name
            .as_ref()
            .map(|data| self.decrypt_name(data))
            .transpose()?
            .flatten();
        let about = encrypted_profile
            .about
            .as_ref()
            .map(|data| self.decrypt_about(data))
            .transpose()?;
        let about_emoji = encrypted_profile
            .about_emoji
            .as_ref()
            .map(|data| self.decrypt_emoji(data))
            .transpose()?;
        // A stale, malformed, or improperly signed payment address shouldn't
        // fail the whole profile; surface it as absent instead. Java:
        // ProfileUtils.decryptAndVerifyMobileCoinAddress.
        let payment_address = encrypted_profile
            .payment_address
            .as_ref()
            .and_then(|data| self.decrypt_payment_address(data).ok())
            .filter(|address| {
                verify_payment_address_signature(
                    address,
                    encrypted_profile.identity_key.as_deref(),
                )
            })
            .map(|address| address.encode_to_vec());

        Ok(Profile {
            name,
            about,
            about_emoji,
            avatar: encrypted_profile.avatar,
            unrestricted_unidentified_access: encrypted_profile
                .unrestricted_unidentified_access,
            payment_address,
        })
    }

    pub fn decrypt_avatar(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProfileCipherError> {
        self.decrypt_and_unpad(bytes)
    }

    /// Encrypt an avatar image for upload. No padding is applied.
    ///
    /// Java: `ProfileCipherOutputStream` (which is plain AES-GCM streaming;
    /// avatars are small enough to encrypt in one go).
    pub fn encrypt_avatar<R: RngCore + CryptoRng>(
        &self,
        bytes: Vec<u8>,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        self.encrypt_raw(bytes, csprng)
    }

    /// Encrypt a [`PaymentAddress`][crate::proto::PaymentAddress] for the
    /// `paymentAddress` profile field (length-prefixed, padded to a fixed
    /// 554-byte bracket like Signal-Android).
    pub fn encrypt_payment_address<R: RngCore + CryptoRng>(
        &self,
        payment_address: &crate::proto::PaymentAddress,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let bytes = payment_address.encode_to_vec();
        self.pad_and_encrypt_with_length(
            &bytes,
            &[PAYMENT_ADDRESS_CONTENT_SIZE],
            csprng,
        )
    }

    /// Decrypt the `paymentAddress` profile field.
    pub fn decrypt_payment_address(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<crate::proto::PaymentAddress, ProfileCipherError> {
        let plaintext = self.decrypt_with_length(bytes.as_ref())?;
        Ok(crate::proto::PaymentAddress::decode(&plaintext[..])?)
    }

    pub fn encrypt_name<'inp, R: RngCore + CryptoRng>(
        &self,
        name: impl std::borrow::Borrow<ProfileName<&'inp str>>,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let name = name.borrow();
        let bytes = name.serialize();
        self.pad_and_encrypt(bytes, NAME_PADDING_BRACKETS, csprng)
    }

    pub fn decrypt_name(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Option<ProfileName<String>>, ProfileCipherError> {
        let bytes = bytes.as_ref();

        let plaintext = self.decrypt_and_unpad(bytes)?;

        Ok(ProfileName::<String>::deserialize(&plaintext)?)
    }

    pub fn encrypt_about<R: RngCore + CryptoRng>(
        &self,
        about: String,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let bytes = about.into_bytes();
        self.pad_and_encrypt(bytes, ABOUT_PADDING_BRACKETS, csprng)
    }

    pub fn decrypt_about(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<String, ProfileCipherError> {
        let bytes = bytes.as_ref();

        let plaintext = self.decrypt_and_unpad(bytes)?;

        // XXX This re-allocates.
        Ok(std::str::from_utf8(&plaintext)?.into())
    }

    pub fn encrypt_emoji<R: RngCore + CryptoRng>(
        &self,
        emoji: String,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let bytes = emoji.into_bytes();
        self.pad_and_encrypt(bytes, &[EMOJI_PADDED_LENGTH], csprng)
    }

    pub fn decrypt_emoji(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<String, ProfileCipherError> {
        let bytes = bytes.as_ref();

        let plaintext = self.decrypt_and_unpad(bytes)?;

        // XXX This re-allocates.
        Ok(std::str::from_utf8(&plaintext)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_name::ProfileName;
    use rand::Rng;
    use zkgroup::profiles::ProfileKey;

    #[test]
    fn roundtrip_name() {
        let names = [
            "Me and my guitar", // shorter that 53
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", // one shorter than 53
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzx", // exactly 53
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzxf", // one more than 53
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzxfoobar", // a bit more than 53
        ];

        // Test the test cases
        assert_eq!(names[1].len(), NAME_PADDED_LENGTH_1 - 1);
        assert_eq!(names[2].len(), NAME_PADDED_LENGTH_1);
        assert_eq!(names[3].len(), NAME_PADDED_LENGTH_1 + 1);

        let mut rng = rand::rng();
        let some_randomness = rng.random();
        let profile_key = ProfileKey::generate(some_randomness);
        let cipher = ProfileCipher::new(profile_key);
        for name in &names {
            let profile_name = ProfileName::<&str> {
                given_name: name,
                family_name: None,
            };
            assert_eq!(profile_name.serialize().len(), name.len());
            let encrypted =
                cipher.encrypt_name(&profile_name, &mut rng).unwrap();
            let decrypted = cipher.decrypt_name(encrypted).unwrap().unwrap();

            assert_eq!(decrypted.as_ref(), profile_name);
            assert_eq!(decrypted.serialize(), profile_name.serialize());
            assert_eq!(&decrypted.given_name, name);
        }
    }

    #[test]
    fn roundtrip_about() {
        let abouts = [
            "Me and my guitar", // shorter that 53
        ];

        let mut rng = rand::rng();
        let some_randomness = rng.random();
        let profile_key = ProfileKey::generate(some_randomness);
        let cipher = ProfileCipher::new(profile_key);

        for &about in &abouts {
            let encrypted =
                cipher.encrypt_about(about.into(), &mut rng).unwrap();
            let decrypted = cipher.decrypt_about(encrypted).unwrap();

            assert_eq!(decrypted, about);
        }
    }

    #[test]
    fn roundtrip_payment_address() {
        use crate::proto::{payment_address, PaymentAddress};

        let mut rng = rand::rng();
        let some_randomness = rng.random();
        let profile_key = ProfileKey::generate(some_randomness);
        let cipher = ProfileCipher::new(profile_key);

        let address = PaymentAddress {
            address: Some(payment_address::Address::MobileCoin(
                payment_address::MobileCoin {
                    public_address: Some(vec![0xAB; 100]),
                    signature: Some(vec![0xCD; 64]),
                },
            )),
        };
        let encrypted =
            cipher.encrypt_payment_address(&address, &mut rng).unwrap();
        // 4-byte length prefix + content padded to 554, plus 28 bytes
        // AES-GCM overhead; base64 of this is the fixed 776-char field.
        assert_eq!(encrypted.len(), 554 + 28);
        let decrypted = cipher.decrypt_payment_address(&encrypted).unwrap();
        assert_eq!(decrypted, address);
    }

    #[test]
    fn payment_address_signature_verification() {
        use crate::proto::{payment_address, PaymentAddress};
        use libsignal_protocol::IdentityKeyPair;

        let mut rng = rand::rng();
        let key_pair = IdentityKeyPair::generate(&mut rng);
        let address_bytes = vec![0x42; 100];
        let signature = key_pair
            .private_key()
            .calculate_signature(&address_bytes, &mut rng)
            .unwrap();

        let address = PaymentAddress {
            address: Some(payment_address::Address::MobileCoin(
                payment_address::MobileCoin {
                    public_address: Some(address_bytes.clone()),
                    signature: Some(signature.to_vec()),
                },
            )),
        };
        let identity = key_pair.identity_key().serialize();
        assert!(verify_payment_address_signature(&address, Some(&identity)));

        // Wrong identity key → rejected.
        let other = IdentityKeyPair::generate(&mut rng);
        let other_identity = other.identity_key().serialize();
        assert!(!verify_payment_address_signature(
            &address,
            Some(&other_identity)
        ));
        // Missing identity key → rejected.
        assert!(!verify_payment_address_signature(&address, None));
    }

    #[test]
    fn roundtrip_avatar() {
        let mut rng = rand::rng();
        let some_randomness = rng.random();
        let profile_key = ProfileKey::generate(some_randomness);
        let cipher = ProfileCipher::new(profile_key);

        // Trailing zero bytes must survive (decrypt_avatar strips padding,
        // but avatars are not padded — content ending in zeroes is the one
        // lossy case, mirroring upstream Java behavior).
        let avatar = vec![0x89, 0x50, 0x4E, 0x47, 0x01, 0x02, 0x03];
        let encrypted =
            cipher.encrypt_avatar(avatar.clone(), &mut rng).unwrap();
        assert_eq!(encrypted.len(), avatar.len() + 28);
        let decrypted = cipher.decrypt_avatar(&encrypted).unwrap();
        assert_eq!(decrypted, avatar);
    }

    #[test]
    fn roundtrip_emoji() {
        let emojii = ["❤️", "💩", "🤣", "😲", "🐠"];

        let mut rng = rand::rng();
        let some_randomness = rng.random();
        let profile_key = ProfileKey::generate(some_randomness);
        let cipher = ProfileCipher::new(profile_key);

        for &emoji in &emojii {
            let encrypted =
                cipher.encrypt_emoji(emoji.into(), &mut rng).unwrap();
            let decrypted = cipher.decrypt_emoji(encrypted).unwrap();

            assert_eq!(decrypted, emoji);
        }
    }
}
