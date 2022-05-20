use bincode::{deserialize, serialize};
use bitflags::bitflags;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use data_encoding::{DecodeError, BASE64};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use std::str::FromStr;
use thiserror::Error;

const VERSION_NUMBER: u8 = 3;

#[derive(Debug, Error)]
pub enum LicenseTypeError {
    #[error("Invalid license type")]
    InvalidType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseType {
    Basic,
    Pro,
    ChinaBasic,
    ChinaPro,
    Business,
}

impl LicenseType {
    pub fn to_byte(&self) -> u8 {
        use LicenseType::*;
        match &self {
            Basic => 0,
            Pro => 1,
            ChinaBasic => 3,
            ChinaPro => 4,
            Business => 102,
        }
    }
}

impl TryFrom<u8> for LicenseType {
    type Error = LicenseTypeError;

    fn try_from(bits: u8) -> Result<Self, Self::Error> {
        use LicenseType::*;
        match &bits {
            0 => Ok(Basic),
            1 => Ok(Pro),
            3 => Ok(ChinaBasic),
            4 => Ok(ChinaPro),
            102 => Ok(Business),
            _ => Err(LicenseTypeError::InvalidType),
        }
    }
}

bitflags! {
    #[rustfmt::skip]
    /// These flags override the default functionality of a license type
    struct LicenseFlags: u16 {
        const PERPETUAL = 0b00000000_00000001;
        const TRIAL     = 0b00000000_00000010;
        const OFFLINE   = 0b00000000_00000100;
    }
}

#[derive(Debug, Error)]
pub enum ParseLicenseError {
    #[error("Invalid license format")]
    InvalidFormat,
    #[error("This is a parser for V3")]
    WrongVersion(u8),
}

impl From<std::io::Error> for ParseLicenseError {
    fn from(_: std::io::Error) -> Self {
        ParseLicenseError::InvalidFormat
    }
}

impl From<LicenseTypeError> for ParseLicenseError {
    fn from(_: LicenseTypeError) -> Self {
        ParseLicenseError::InvalidFormat
    }
}

impl From<DecodeError> for ParseLicenseError {
    fn from(_: DecodeError) -> Self {
        ParseLicenseError::InvalidFormat
    }
}

impl From<bincode::Error> for ParseLicenseError {
    fn from(_: bincode::Error) -> Self {
        ParseLicenseError::InvalidFormat
    }
}

/// A license with signature
pub struct SignedLicense {
    pub license: License,
    pub signature: Signature,
}

impl SignedLicense {
    /// Encode the signed license for serialization
    pub fn encode(&self) -> String {
        format!(
            "{}.{}",
            self.license.encode(),
            BASE64.encode(&serialize(&self.signature).unwrap())
        )
    }

    /// Given a public key, check if the signature is correct for the license
    pub fn verify(&self, key: PublicKey) -> bool {
        key.verify(&self.license.as_bytes(), &self.signature)
            .is_ok()
    }
}

impl FromStr for SignedLicense {
    type Err = ParseLicenseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (license, signature) = s.split_once(".").ok_or(ParseLicenseError::InvalidFormat)?;
        Ok(SignedLicense {
            license: license.parse()?,
            signature: deserialize(&BASE64.decode(signature.as_bytes())?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct License {
    pub license_type: LicenseType,
    pub expiration_year: u16,
    pub expiration_month: u8,
    pub expiration_day: u8,
    pub user_id: u32,
    pub perpetual: bool,
    pub trial: bool,
    pub computer_id: Option<String>,
}

impl License {
    /// Returns the byte encoded version of the license.
    /// Mainly for validating the signature.
    pub fn as_bytes(&self) -> Vec<u8> {
        let License {
            license_type,
            expiration_year,
            expiration_month,
            expiration_day,
            user_id,
            perpetual,
            trial,
            computer_id,
        } = self;
        let mut bytes = Vec::new();
        bytes.write_u8(VERSION_NUMBER).unwrap();
        bytes.write_u8(license_type.to_byte()).unwrap();
        let mut flags = LicenseFlags::empty();
        flags.set(LicenseFlags::PERPETUAL, *perpetual);
        flags.set(LicenseFlags::TRIAL, *trial);
        flags.set(LicenseFlags::OFFLINE, computer_id.is_some());
        bytes.write_u16::<BigEndian>(flags.bits).unwrap();
        bytes.write_u16::<BigEndian>(*expiration_year).unwrap();
        bytes.write_u8(*expiration_month).unwrap();
        bytes.write_u8(*expiration_day).unwrap();
        let computer_id = computer_id.clone().unwrap_or("0".to_string());
        let computer_id = u32::from_str_radix(&computer_id, 16).unwrap();
        bytes.write_u32::<BigEndian>(computer_id).unwrap();
        bytes.write_u32::<BigEndian>(*user_id).unwrap();
        bytes
    }

    pub fn encode(&self) -> String {
        format!("{}", BASE64.encode(&self.as_bytes()))
    }

    pub fn sign(self, key: Keypair) -> SignedLicense {
        let signature = key.sign(&self.as_bytes());
        SignedLicense {
            license: self,
            signature,
        }
    }
}

impl FromStr for License {
    type Err = ParseLicenseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let temp = BASE64.decode(s.as_bytes())?;
        let mut b = temp.as_slice();
        let version = b.read_u8()?;
        if version != VERSION_NUMBER {
            return Err(ParseLicenseError::WrongVersion(version));
        }
        let license_type = b.read_u8()?;
        let flags = LicenseFlags::from_bits_truncate(b.read_u16::<BigEndian>()?);
        let year = b.read_u16::<BigEndian>()?;
        let month = b.read_u8()?;
        let day = b.read_u8()?;
        let computer_id = b.read_u32::<BigEndian>()?;
        let computer_id = if flags.contains(LicenseFlags::OFFLINE) {
            Some(computer_id)
        } else {
            None
        };
        let user_id = b.read_u32::<BigEndian>()?;
        Ok(License {
            license_type: license_type.try_into()?,
            expiration_year: year,
            expiration_month: month,
            expiration_day: day,
            user_id: user_id,
            perpetual: flags.contains(LicenseFlags::PERPETUAL),
            trial: flags.contains(LicenseFlags::TRIAL),
            computer_id: computer_id.and_then(|u| Some(format!("{u:08X}"))),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{License, LicenseType, SignedLicense};
    use ed25519::pkcs8::{DecodePublicKey, PublicKeyBytes};
    use ed25519_dalek::PublicKey;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref PUBLIC_KEY: PublicKey = {
            let public_key_file = std::fs::read_to_string("keys/public.pem").unwrap();
            let public_key: PublicKeyBytes =
                PublicKeyBytes::from_public_key_pem(&public_key_file).unwrap();
            PublicKey::from_bytes(&public_key.to_bytes()).unwrap()
        };
        static ref VALID_LICENSE_1: License = License {
            license_type: LicenseType::Pro,
            expiration_year: 0,
            expiration_month: 0,
            expiration_day: 0,
            user_id: 257,
            perpetual: true,
            trial: false,
            computer_id: None,
        };
        static ref VALID_LICENSE_2: License = License {
            license_type: LicenseType::Business,
            expiration_year: 2022,
            expiration_month: 1,
            expiration_day: 1,
            user_id: 257,
            perpetual: false,
            trial: false,
            computer_id: Some("12345678".to_string()),
        };
        static ref INVALID_LICENSE_1: License = License {
            license_type: LicenseType::Pro,
            expiration_year: 0,
            expiration_month: 0,
            expiration_day: 0,
            user_id: 257,
            perpetual: true,
            trial: false,
            computer_id: None,
        };
        static ref INVALID_LICENSE_2: License = License {
            license_type: LicenseType::Business,
            expiration_year: 2022,
            expiration_month: 1,
            expiration_day: 1,
            user_id: 261,
            perpetual: false,
            trial: false,
            computer_id: Some("12345678".to_string()),
        };
    }

    const VALID_LICENSE_STR_1: &str = "AwEAAQAAAAAAAAAAAAABAQ==.BDwoNrdFMMtuA0XVY+Cz0nlZArttAkCZX7UK6/A/imxlOH6VaFMOg0CvpmZnDGz6C8QY1P6GyfQS6XjnC5JLAA==";
    const VALID_LICENSE_STR_2: &str = "A2YABAfmAQESNFZ4AAABAQ==.QA5PaRYuiff+5v9NI/meWrOrg9M8/XuGIR+6+8OO/Exx14S0+GQZ1WYdWcZd9vJINqVToS4dkPdlNcaCKJKaDg==";

    // Bad signature
    const INVALID_LICENSE_STR_1: &str = "AwEAAQAAAAAAAAAAAAABAQ==.BDwoNrdFMMtuA0XVY+Cz0nlZArttAkCZX7UK6/A/imxlOH6VaFMOg0CvpmZnDGz6C8QY1P6GyfQS6XjnD5JLAA==";
    //                                                                                                                                            C

    // User ID changed, but signature is the same
    const INVALID_LICENSE_STR_2: &str = "A2YABAfmAQESNFZ4AAABBQ==.QA5PaRYuiff+5v9NI/meWrOrg9M8/XuGIR+6+8OO/Exx14S0+GQZ1WYdWcZd9vJINqVToS4dkPdlNcaCKJKaDg==";
    //                                                       A

    fn verify_license(license_str: &str) -> bool {
        let s_license: SignedLicense = license_str.parse().unwrap();
        s_license.verify(*PUBLIC_KEY)
    }

    fn valid_license(license_str: &str, license: &License) -> bool {
        let s_license: SignedLicense = license_str.parse().unwrap();
        s_license.license == *license
    }

    #[test]
    fn test_license_validity() {
        assert!(verify_license(VALID_LICENSE_STR_1));
        assert!(!verify_license(INVALID_LICENSE_STR_1));
        assert!(verify_license(VALID_LICENSE_STR_2));
        assert!(!verify_license(INVALID_LICENSE_STR_2));
    }

    #[test]
    fn test_license_content() {
        assert!(valid_license(VALID_LICENSE_STR_1, &VALID_LICENSE_1));
        assert!(valid_license(INVALID_LICENSE_STR_1, &INVALID_LICENSE_1));
        assert!(valid_license(VALID_LICENSE_STR_2, &VALID_LICENSE_2));
        assert!(valid_license(INVALID_LICENSE_STR_2, &INVALID_LICENSE_2));
    }
}
