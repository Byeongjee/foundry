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
use bls_sigs_ref::{BLSSigCore as BlsSigCore, BLSSignatureBasic as BlsSignatureBasic};
use crypto::blake256;
use pairing_plus::bls12_381::{Fr, G1Compressed, G2Compressed, G1, G2};
use pairing_plus::{CurveAffine, CurveProjective, EncodedPoint};
use primitives::{H256, H384, H768};
use rand_core::OsRng;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rustc_hex::{FromHex, ToHex};
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

pub const BLS_SIGNATURE_SIZE: usize = 48;
pub const BLS_PUBLIC_SIZE: usize = 96;

#[derive(Copy, Clone)]
pub struct BlsSignature(H384);

impl BlsSignature {
    pub fn random() -> Self {
        BlsSignature(H384::random())
    }

    fn from_point(point: G1) -> Self {
        BlsSignature(H384::from(point.into_affine().into_compressed().as_ref()))
    }
    
    fn into_point(&self) -> Result<G1, Error> {
        match G1Compressed::from((self.0).0).into_affine() {
            Ok(point) => Ok(point.into_projective()),
            Err(_) => Err(Error::InvalidSignature)
        }
    }
}

impl PartialEq for BlsSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for BlsSignature {}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "BlsSignature: {}", self.0.to_hex())
    }
}

impl fmt::Display for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0.to_hex())
    }
}

impl FromStr for BlsSignature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.from_hex() {
            Ok(ref hex) if hex.len() == BLS_SIGNATURE_SIZE => {
                let mut data = [0; BLS_SIGNATURE_SIZE];
                data.copy_from_slice(&hex[0..BLS_SIGNATURE_SIZE]);
                Ok(BlsSignature(H384::from(data)))
            }
            _ => Err(Error::InvalidSignature),
        }
    }
}

impl Hash for BlsSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Default for BlsSignature {
    fn default() -> Self {
        BlsSignature(H384::default())
    }
}
impl Encodable for BlsSignature {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.rlp_append(s);
    }
}

impl Decodable for BlsSignature {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let data = H384::decode(rlp)?;
        Ok(BlsSignature(data))
    }
}

impl Serialize for BlsSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        self.0.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for BlsSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>, {
        let data = H384::deserialize(deserializer)?;
        Ok(BlsSignature(data))
    }
}

pub struct BlsPublicUnverified(H768);
#[derive(Copy, Clone)]
pub struct BlsPublic(G2);

impl BlsPublic {
    pub fn random() -> Self {
        let mut rng = OsRng::default();
        BlsPublic(G2::random(&mut rng))
    }

    // Need to sign on BLSPublic for proof of posession
    pub fn hash_with_value<B: AsRef<[u8]>>(&self, value: B) -> Message {
        let mut data = self.compressed().as_ref().to_vec();
        data.extend(value.as_ref());
        blake256(data)
    }

    fn compressed(&self) -> G2Compressed {
        self.0.into_affine().into_compressed()
    }

    fn to_hex(&self) -> String {
        self.compressed().as_ref().to_hex()
    }

    fn from_unverified(unverified: BlsPublicUnverified) -> Result<Self, Error> {
        let point = match G2Compressed::from((unverified.0).0).into_affine() {
            Ok(affine) => affine.into_projective(),
            Err(_) => return Err(Error::InvalidPublic),
        };
        Ok(BlsPublic(point))
    }
}

impl PartialEq for BlsPublicUnverified {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for BlsPublicUnverified {}

impl Hash for BlsPublic {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.compressed().as_ref().hash(state);
    }
}

impl Ord for BlsPublicUnverified {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for BlsPublicUnverified {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Encodable for BlsPublic {
    fn rlp_append(&self, s: &mut RlpStream) {
        let data: H768 = self.compressed().as_ref().into();
        data.rlp_append(s);
    }
}

impl Decodable for BlsPublicUnverified {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let data = H768::decode(rlp)?;
        Ok(BlsPublicUnverified(data))
    }
}

impl Serialize for BlsPublic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        let data: H768 = self.compressed().as_ref().into();
        data.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for BlsPublicUnverified {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>, {
        let data = H768::deserialize(deserializer)?;
        Ok(BlsPublicUnverified(data))
    }
}

impl fmt::Debug for BlsPublicUnverified {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "BlsPublic: {}", self.0.to_hex())
    }
}

impl fmt::Display for BlsPublic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for BlsPublic {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.from_hex() {
            Ok(ref hex) if hex.len() == BLS_PUBLIC_SIZE => {
                let mut data = [0; BLS_PUBLIC_SIZE];
                data.copy_from_slice(&hex[0..BLS_PUBLIC_SIZE]);
                let g2 = match G2Compressed::from(data).into_affine() {
                    Ok(g2) => g2.into_projective(),
                    _ => return Err(Error::InvalidPublic),
                };
                Ok(BlsPublic(g2))
            }
            _ => Err(Error::InvalidPublic),
        }
    }
}

#[derive(Copy, Clone)]
pub struct BlsPrivate(Fr);

pub struct BlsKeyPair {
    private: BlsPrivate,
    public: BlsPublic,
}

impl BlsKeyPair {
    pub fn from_secret<B: AsRef<[u8]>>(secret: B) -> Self {
        let (x_prime, pk) = G1::keygen(secret);
        BlsKeyPair {
            private: BlsPrivate(x_prime),
            public: BlsPublic(pk),
        }
    }

    pub fn private(&self) -> &BlsPrivate {
        &self.private
    }

    pub fn public(&self) -> &BlsPublic {
        &self.public
    }
}

impl From<H256> for BlsPrivate {
    fn from(msg: H256) -> Self {
        let (private, _public) = <G1 as BlsSigCore>::keygen(msg);
        BlsPrivate(private)
    }
}

pub fn sign_bls(private: &BlsPrivate, message: &Message) -> BlsSignature {
    let point = <G1 as BlsSignatureBasic>::sign(private.0, message);
    BlsSignature::from_point(point)
}

pub fn aggregate_signatures_bls(signatures: &[BlsSignature]) -> Result<BlsSignature, Error> {
    let signatures: Result<Vec<_>, _> = signatures.iter().map(|sig| sig.into_point()).collect();
    let aggregated_signatures = <G1 as BlsSigCore>::aggregate(&signatures?);
    Ok(BlsSignature::from_point(aggregated_signatures))
}

pub fn verify_aggregated_bls(
    publics: &[BlsPublic],
    aggregated_signature: &BlsSignature,
    message: &Message,
) -> Result<bool, Error> {
    let aggregated_public = aggregate_publics_bls(publics);
    Ok(verify_bls(&aggregated_public, &aggregated_signature, message)?)
}

fn aggregate_publics_bls(publics: &[BlsPublic]) -> BlsPublic {
    let publics_g2: Vec<_> = publics.iter().map(|public| public.0).collect();
    let aggregated_publics_g2 = <G2 as BlsSigCore>::aggregate(&publics_g2);
    BlsPublic(aggregated_publics_g2)
}

pub fn verify_bls(public: &BlsPublic, signature: &BlsSignature, message: &Message) -> Result<bool, Error> {
    let public = public.0;
    let signature = signature.into_point()?;
    Ok(BlsSignatureBasic::verify(public, signature, message))
}
