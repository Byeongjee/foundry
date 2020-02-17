// Copyright 2018-2020 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::{Error, Message};
use bls_sigs_ref::{BLSSigCore, BLSSignatureBasic};
use crypto::blake256;
use pairing_plus::bls12_381::{Fr, G1Compressed, G2Compressed, G1, G2};
use pairing_plus::{CurveAffine, CurveProjective, EncodedPoint};
use primitives::{H256, H384, H768};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rustc_hex::{FromHex, ToHex};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

pub const BLS_SIGNATURE_SIZE: usize = 48;
pub const BLS_PUBLIC_SIZE: usize = 96;

#[derive(Copy, Clone)]
pub struct BLSSignature([u8; BLS_SIGNATURE_SIZE]);

impl BLSSignature {
    pub fn random() -> Self {
        let bytes = H384::random();
        BLSSignature(bytes.into())
    }

    fn g1(&self) -> Result<G1, Error> {
        match G1Compressed::from(self.0).into_affine() {
            Ok(signature) => Ok(signature.into_projective()),
            Err(_) => Err(Error::InvalidSignature),
        }
    }
}

impl PartialEq for BLSSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for BLSSignature {}

impl fmt::Debug for BLSSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("BLSSignature").field("r", &self.0[0..BLS_SIGNATURE_SIZE].to_hex()).finish()
    }
}

impl fmt::Display for BLSSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0.to_hex())
    }
}

impl FromStr for BLSSignature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.from_hex() {
            Ok(ref hex) if hex.len() == BLS_SIGNATURE_SIZE => {
                let mut data = [0; BLS_SIGNATURE_SIZE];
                data.copy_from_slice(&hex[0..BLS_SIGNATURE_SIZE]);
                Ok(BLSSignature(data))
            }
            _ => Err(Error::InvalidSignature),
        }
    }
}


impl Hash for BLSSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        H384::from(self.0).hash(state);
    }
}

impl Default for BLSSignature {
    fn default() -> Self {
        BLSSignature([0; BLS_SIGNATURE_SIZE])
    }
}
impl Encodable for BLSSignature {
    fn rlp_append(&self, s: &mut RlpStream) {
        let data: H384 = self.0.into();
        data.rlp_append(s);
    }
}

impl Decodable for BLSSignature {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let data = H384::decode(rlp)?;
        Ok(BLSSignature::from(data))
    }
}

impl From<H384> for BLSSignature {
    fn from(bytes: H384) -> Self {
        BLSSignature(bytes.into())
    }
}

impl From<G1> for BLSSignature {
    fn from(g1: G1) -> Self {
        let bytes: H384 = H384::from(G1Compressed::from_affine(g1.into_affine()).as_ref());
        BLSSignature::from(bytes)
    }
}

impl Serialize for BLSSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        let data: H384 = self.0.into();
        data.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for BLSSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>, {
        let data = H384::deserialize(deserializer)?;
        Ok(Self::from(data))
    }
}


#[derive(Copy, Clone)]
pub struct BLSPublic([u8; BLS_PUBLIC_SIZE]);

impl BLSPublic {
    pub fn random() -> Self {
        let bytes = H768::random();
        BLSPublic(bytes.into())
    }

    // Need to sign on BLSPublic for proof of posession
    pub fn hash(&self) -> Message {
        blake256(self.0.as_ref())
    }

    fn g2(&self) -> Result<G2, Error> {
        match G2Compressed::from(self.0).into_affine() {
            Ok(public) => Ok(public.into_projective()),
            Err(_) => Err(Error::InvalidPublic),
        }
    }
}

impl PartialEq for BLSPublic {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for BLSPublic {}

impl Hash for BLSPublic {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state);
    }
}

impl Ord for BLSPublic {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for BLSPublic {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Encodable for BLSPublic {
    fn rlp_append(&self, s: &mut RlpStream) {
        let data: H768 = self.0.into();
        data.rlp_append(s);
    }
}

impl Decodable for BLSPublic {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let data = H768::decode(rlp)?;
        Ok(BLSPublic::from(data))
    }
}

impl From<H768> for BLSPublic {
    fn from(bytes: H768) -> Self {
        BLSPublic(bytes.into())
    }
}

impl Serialize for BLSPublic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        let data: H768 = self.0.into();
        data.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for BLSPublic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>, {
        let data = H768::deserialize(deserializer)?;
        Ok(Self::from(data))
    }
}

impl From<G2> for BLSPublic {
    fn from(g2: G2) -> Self {
        let bytes: H768 = H768::from(G2Compressed::from_affine(g2.into_affine()).as_ref());
        BLSPublic::from(bytes)
    }
}


impl fmt::Debug for BLSPublic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("BLSPublic").field("r", &self.0[0..BLS_PUBLIC_SIZE].to_hex()).finish()
    }
}

impl fmt::Display for BLSPublic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0.to_hex())
    }
}


impl FromStr for BLSPublic {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.from_hex() {
            Ok(ref hex) if hex.len() == BLS_PUBLIC_SIZE => {
                let mut data = [0; BLS_PUBLIC_SIZE];
                data.copy_from_slice(&hex[0..BLS_PUBLIC_SIZE]);
                Ok(BLSPublic(data))
            }
            _ => Err(Error::InvalidPublic),
        }
    }
}

#[derive(Copy, Clone)]
pub struct BLSPrivate(Fr);

pub struct BLSKeyPair {
    private: BLSPrivate,
    public: BLSPublic,
}

impl BLSKeyPair {
    pub fn from_secret(msg: H256) -> Self {
        let (private, public) = <G1 as BLSSigCore>::keygen(msg);
        Self {
            private: BLSPrivate(private),
            public: BLSPublic::from(public),
        }
    }

    pub fn generate_keypair<B: AsRef<[u8]>>(secret: B) -> Self {
        let (x_prime, pk) = G1::keygen(secret);
        BLSKeyPair {
            private: BLSPrivate(x_prime),
            public: BLSPublic::from(pk),
        }
    }

    pub fn private(&self) -> &BLSPrivate {
        &self.private
    }

    pub fn public(&self) -> &BLSPublic {
        &self.public
    }
}

impl From<H256> for BLSPrivate {
    fn from(msg: H256) -> Self {
        let (private, _public) = <G1 as BLSSigCore>::keygen(msg);
        BLSPrivate(private)
    }
}

pub fn sign_bls(private: &BLSPrivate, message: &Message) -> BLSSignature {
    let signature = <G1 as BLSSignatureBasic>::sign(private.0, message);
    BLSSignature::from(signature)
}

pub fn aggregate_signatures_bls(signatures: &[BLSSignature]) -> BLSSignature {
    let signatures_g1: Vec<_> = signatures.iter().map(|sig| sig.g1().unwrap()).collect();
    let aggregated_signatures_g1 = <G1 as BLSSigCore>::aggregate(&signatures_g1);
    BLSSignature::from(aggregated_signatures_g1)
}

pub fn verify_aggregated_bls(
    publics: &[BLSPublic],
    aggregated_signature: &BLSSignature,
    message: &Message,
) -> Result<bool, Error> {
    let aggregated_public = aggregate_publics_bls(publics)?;
    verify_bls(&aggregated_public, &aggregated_signature, message)
}

fn aggregate_publics_bls(publics: &[BLSPublic]) -> Result<BLSPublic, Error> {
    let publics_g2: Result<Vec<_>, _> = publics.iter().map(|public| public.g2()).collect();
    let publics_g2 = publics_g2?;
    let aggregated_publics_g2 = <G2 as BLSSigCore>::aggregate(&publics_g2);
    Ok(BLSPublic::from(aggregated_publics_g2))
}
pub fn verify_bls(public: &BLSPublic, signature: &BLSSignature, message: &Message) -> Result<bool, Error> {
    let public = public.g2()?;
    let signature = signature.g1()?;
    Ok(BLSSignatureBasic::verify(public, signature, message))
}
