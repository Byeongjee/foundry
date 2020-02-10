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
use pairing_plus::bls12_381::{Fr, G1Compressed, G2Compressed, G1, G2};
use pairing_plus::{CurveAffine, CurveProjective, EncodedPoint};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Copy, Clone, Debug)]
pub struct BLSSignature(G1Compressed);

impl BLSSignature {
    fn g1(&self) -> Result<G1, Error> {
        match self.0.into_affine() {
            Ok(signature) => Ok(signature.into_projective()),
            Err(_) => Err(Error::InvalidSignature),
        }
    }
}

impl PartialEq for BLSSignature {
    fn eq(&self, other: &BLSSignature) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Encodable for BLSSignature {
    fn rlp_append(&self, s: &mut RlpStream) {
        let data: &[u8] = self.0.as_ref();
        assert_eq!(data.len(), 48);
        s.append(&data);
    }
}

impl Decodable for BLSSignature {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let data = rlp.data()?;
        if data.len() != 48 {
            return Err(DecoderError::Custom("BLS Signature must be 48 bytes long"))
        }
        let mut array = [0; 48];
        array.copy_from_slice(data);
        let g1_compressed = G1Compressed::from(array);
        Ok(BLSSignature(g1_compressed))
    }
}

impl From<G1> for BLSSignature {
    fn from(g1: G1) -> Self {
        let g1_affine = g1.into_affine();
        BLSSignature(G1Compressed::from_affine(g1_affine))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct BLSPublic(G2Compressed);

impl BLSPublic {
    fn g2(&self) -> Result<G2, Error> {
        match self.0.into_affine() {
            Ok(public) => Ok(public.into_projective()),
            Err(_) => Err(Error::InvalidPublic),
        }
    }
}

impl From<G2> for BLSPublic {
    fn from(g2: G2) -> Self {
        let g2_affine = g2.into_affine();
        BLSPublic(G2Compressed::from_affine(g2_affine))
    }
}

impl Encodable for BLSPublic {
    fn rlp_append(&self, s: &mut RlpStream) {
        let data: &[u8] = self.0.as_ref();
        assert_eq!(data.len(), 96);
        s.append(&data);
    }
}

impl Decodable for BLSPublic {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let data = rlp.data()?;
        if data.len() != 96 {
            return Err(DecoderError::Custom("BLS Public key must be 96 bytes long"))
        }
        let mut array = [0; 96];
        array.copy_from_slice(data);
        let g2_compressed = G2Compressed::from(array);
        Ok(BLSPublic(g2_compressed))
    }
}

pub struct BLSPrivate(Fr);

pub fn sign_bls(private: &BLSPrivate, message: &Message) -> BLSSignature {
    let signature = <G1 as BLSSignatureBasic>::sign(private.0, message);
    BLSSignature::from(signature)
}

pub fn aggregate_signatures_bls(signatures: &[BLSSignature]) -> BLSSignature {
    let signatures_g1: Vec<_> = signatures.iter().map(|sig| sig.g1().unwrap()).collect();
    let aggregated_signatures_g1 = <G1 as BLSSigCore>::aggregate(&signatures_g1);
    BLSSignature::from(aggregated_signatures_g1)
}

//TODO: Change to modified BLS
pub fn verify_aggregated_bls(
    publics: &[BLSPublic],
    aggregated_signature: &BLSSignature,
    message: &Message,
) -> Result<bool, Error> {
    let publics_g2: Result<Vec<_>, _> = publics.iter().map(|public| public.g2()).collect();
    let publics_g2 = publics_g2?;
    let aggregated_publics_g2 = <G2 as BLSSigCore>::aggregate(&publics_g2);
    let aggregated_public = BLSPublic::from(aggregated_publics_g2);
    verify_bls(&aggregated_public, &aggregated_signature, message)
}

pub fn verify_bls(public: &BLSPublic, signature: &BLSSignature, message: &Message) -> Result<bool, Error> {
    let public = public.g2()?;
    let signature = signature.g1()?;
    Ok(BLSSignatureBasic::verify(public, signature, message))
}
