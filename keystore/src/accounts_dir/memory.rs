// Copyright 2015-2017 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use super::KeyDirectory;
use crate::{Error, SafeAccount};
use ckey::Ed25519Public as Public;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::convert::TryInto;

/// Accounts in-memory storage.
#[derive(Default)]
pub struct MemoryDirectory {
    accounts: RwLock<HashMap<Public, Vec<SafeAccount>>>,
}

impl KeyDirectory for MemoryDirectory {
    fn load(&self) -> Result<Vec<SafeAccount>, Error> {
        Ok(self.accounts.read().values().cloned().flatten().collect())
    }

    fn update(&self, account: SafeAccount) -> Result<SafeAccount, Error> {
        let mut lock = self.accounts.write();
        let accounts = lock.entry(account.pubkey).or_insert_with(Vec::new);
        // If the filename is the same we just need to replace the entry
        accounts.retain(|acc| acc.filename != account.filename);
        accounts.push(account.clone());
        Ok(account)
    }

    fn insert(&self, account: SafeAccount) -> Result<SafeAccount, Error> {
        let mut lock = self.accounts.write();
        let accounts = lock.entry(account.pubkey).or_insert_with(Vec::new);
        accounts.push(account.clone());
        Ok(account)
    }

    fn remove(&self, account: &SafeAccount) -> Result<(), Error> {
        let mut accounts = self.accounts.write();
        let is_empty = if let Some(accounts) = accounts.get_mut(&account.pubkey) {
            if let Some(position) = accounts.iter().position(|acc| acc == account) {
                accounts.remove(position);
            }
            accounts.is_empty()
        } else {
            false
        };
        if is_empty {
            accounts.remove(&account.pubkey);
        }
        Ok(())
    }

    fn unique_repr(&self) -> Result<u64, Error> {
        let mut val = 0u64;
        let accounts = self.accounts.read();
        for acc in accounts.keys() {
            let bytes = acc.as_ref();
            val ^= u64::from_be_bytes(bytes[0..8].try_into().unwrap());
            val ^= u64::from_be_bytes(bytes[8..16].try_into().unwrap());
            val ^= u64::from_be_bytes(bytes[16..24].try_into().unwrap());
            val ^= u64::from_be_bytes(bytes[24..32].try_into().unwrap());
        }
        Ok(val)
    }
}
