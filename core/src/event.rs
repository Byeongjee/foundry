// Copyright 2020 Kodebox, Inc.
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

use crate::db::Key;
use coordinator::validator::Event;
use ctypes::{BlockHash, TxHash};
use primitives::H256;
use rlp::{Decodable, Encodable, Rlp, RlpStream};
use std::hash::Hash;
use std::ops::Deref;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum EventSource {
    Block(BlockHash),
    Transaction(TxHash),
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Events(pub Vec<Event>);

impl Encodable for Events {
    fn rlp_append(&self, _: &mut RlpStream) {
        unimplemented!()
    }
}

impl Decodable for Events {
    fn decode(_rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        unimplemented!()
    }
}

impl Key<Events> for EventSource {
    type Target = H256;

    fn key(&self) -> H256 {
        match self {
            EventSource::Block(hash) => *hash.deref(),
            EventSource::Transaction(hash) => *hash.deref(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EventsWithSource {
    pub source: EventSource,
    pub events: Vec<Event>,
}
