// Copyright 2018 Kodebox, Inc.
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

#![feature(test)]

extern crate codechain_key as ckey;
extern crate test;

use ckey::{
    aggregate_signatures_bls, sign_bls, verify_aggregated_bls, verify_bls, BLSPublic, BLSSignature, Generator, Message,
    Random,
};
use test::Bencher;

#[bench]
fn bls_keygen(b: &mut Bencher) {
    b.iter(|| {
        Random.generate_bls().unwrap()
    })
}

#[bench]
fn bls_messagegen(b: &mut Bencher) {
    b.iter(|| {
        Message::random()
    })
}

#[bench]
fn bls_sign(b: &mut Bencher) {
    b.iter(|| {
        let key_pair = Random.generate_bls().unwrap();
        let message = Message::random();
        sign_bls(key_pair.private(), &message)
    });
}

#[bench]
fn bls_sign_and_verify(b: &mut Bencher) {
    b.iter(|| {
        let key_pair = Random.generate_bls().unwrap();
        let message = Message::random();
        let signature = sign_bls(key_pair.private(), &message);
        assert_eq!(Ok(true), verify_bls(key_pair.public(), &signature, &message));
    });
}

#[bench]
fn bls_get_signatures_30(b: &mut Bencher) {
    bls_get_signatures(30, b)
}

#[bench]
fn bls_aggregate_signatures_30(b: &mut Bencher) {
    bls_aggregate_signatures(30, b)
}

#[bench]
fn bls_aggregate_and_verify_30(b: &mut Bencher) {
    bls_aggregate_and_verify(30, b)
}

#[bench]
fn bls_get_signatures_60(b: &mut Bencher) {
    bls_get_signatures(60, b)
}

#[bench]
fn bls_aggregate_signatures_60(b: &mut Bencher) {
    bls_aggregate_signatures(60, b)
}

#[bench]
fn bls_aggregate_and_verify_60(b: &mut Bencher) {
    bls_aggregate_and_verify(60, b)
}

#[bench]
fn bls_get_signatures_90(b: &mut Bencher) {
    bls_get_signatures(90, b)
}

#[bench]
fn bls_aggregate_signatures_90(b: &mut Bencher) {
    bls_aggregate_signatures(90, b)
}

#[bench]
fn bls_aggregate_and_verify_90(b: &mut Bencher) {
    bls_aggregate_and_verify(90, b)
}

fn bls_get_signatures(num_validators: usize, b: &mut Bencher) {
    b.iter(|| {
        let key_pairs = (0..num_validators).map(|_| Random.generate_bls().unwrap());
        let message = Message::random();
        key_pairs.map(|key_pair| sign_bls(key_pair.private(), &message)).collect::<Vec<BLSSignature>>()
    })
}

fn bls_aggregate_signatures(num_validators: usize, b: &mut Bencher) {
    b.iter(|| {
        let key_pairs = (0..num_validators).map(|_| Random.generate_bls().unwrap());
        let message = Message::random();
        let signatures: Vec<BLSSignature> = key_pairs.map(|key_pair| sign_bls(key_pair.private(), &message)).collect();
        aggregate_signatures_bls(&signatures)
    })
}

fn bls_aggregate_and_verify(num_validators: usize, b: &mut Bencher) {
    b.iter(|| {
        let key_pairs: Vec<_> = (0..num_validators).map(|_| Random.generate_bls().unwrap()).collect();
        let message = Message::random();
        let signatures: Vec<BLSSignature> =
            key_pairs.iter().map(|key_pair| sign_bls(key_pair.private(), &message)).collect();
        let aggregated_signature = aggregate_signatures_bls(&signatures);
        let publics: Vec<BLSPublic> = key_pairs.iter().map(|key_pair| *key_pair.public()).collect();
        assert_eq!(Ok(true), verify_aggregated_bls(&publics, &aggregated_signature, &message))
    })
}
