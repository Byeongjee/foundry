// Copyright 2019-2020 Kodebox, Inc.
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

use super::super::errors;
use super::super::traits::Mempool;
use super::super::types::PendingTransactions;
use ccore::{BlockChainClient, EngineInfo, MiningBlockChainClient, UnverifiedTransaction, VerifiedTransaction};
use cjson::bytes::Bytes;
use ckey::{Ed25519Public as Public, PlatformAddress};
use ctypes::TxHash;
use jsonrpc_core::Result;
use rlp::Rlp;
use std::convert::TryInto;
use std::sync::Arc;

pub struct MempoolClient<C> {
    client: Arc<C>,
}

impl<C> MempoolClient<C> {
    pub fn new(client: Arc<C>) -> Self {
        MempoolClient {
            client,
        }
    }
}

impl<C> Mempool for MempoolClient<C>
where
    C: BlockChainClient + MiningBlockChainClient + EngineInfo + 'static,
{
    fn send_signed_transaction(&self, raw: Bytes) -> Result<TxHash> {
        Rlp::new(&raw.into_vec())
            .as_val()
            .map_err(|e| errors::rlp(&e))
            .and_then(|tx: UnverifiedTransaction| tx.try_into().map_err(errors::transaction_core))
            .and_then(|signed: VerifiedTransaction| {
                let hash = signed.hash();
                match self.client.queue_own_transaction(signed) {
                    Ok(_) => Ok(hash),
                    Err(e) => Err(errors::transaction_core(e)),
                }
            })
            .map(Into::into)
    }

    fn get_error_hint(&self, transaction_hash: TxHash) -> Result<Option<String>> {
        Ok(self.client.error_hint(&transaction_hash))
    }

    fn delete_all_pending_transactions(&self) -> Result<()> {
        self.client.delete_all_pending_transactions();
        Ok(())
    }

    fn get_pending_transactions(
        &self,
        from: Option<u64>,
        to: Option<u64>,
        future_included: Option<bool>,
    ) -> Result<PendingTransactions> {
        if future_included.unwrap_or(false) {
            Ok(self.client.future_pending_transactions(from.unwrap_or(0)..to.unwrap_or(u64::MAX)).into())
        } else {
            Ok(self.client.ready_transactions(from.unwrap_or(0)..to.unwrap_or(u64::MAX)).into())
        }
    }

    fn get_pending_transactions_count(
        &self,
        from: Option<u64>,
        to: Option<u64>,
        future_included: Option<bool>,
    ) -> Result<usize> {
        if future_included.unwrap_or(false) {
            Ok(self.client.future_included_count_pending_transactions(from.unwrap_or(0)..to.unwrap_or(u64::MAX)))
        } else {
            Ok(self.client.count_pending_transactions(from.unwrap_or(0)..to.unwrap_or(u64::MAX)))
        }
    }

    fn get_banned_accounts(&self) -> Result<Vec<PlatformAddress>> {
        let malicious_user_vec = self.client.get_malicious_users();
        let network_id = self.client.network_id();
        Ok(malicious_user_vec.into_iter().map(|address| PlatformAddress::new_v1(network_id, address)).collect())
    }

    fn unban_accounts(&self, prisoner_list: Vec<PlatformAddress>) -> Result<()> {
        let prisoner_vec: Vec<Public> = prisoner_list.into_iter().map(PlatformAddress::into_pubkey).collect();

        self.client.release_malicious_users(prisoner_vec);
        Ok(())
    }

    fn ban_accounts(&self, prisoner_list: Vec<PlatformAddress>) -> Result<()> {
        let prisoner_vec: Vec<Public> = prisoner_list.into_iter().map(PlatformAddress::into_pubkey).collect();

        self.client.imprison_malicious_users(prisoner_vec);
        Ok(())
    }

    fn get_immune_accounts(&self) -> Result<Vec<PlatformAddress>> {
        let immune_user_vec = self.client.get_immune_users();
        let network_id = self.client.network_id();
        Ok(immune_user_vec.into_iter().map(|address| PlatformAddress::new_v1(network_id, address)).collect())
    }

    fn register_immune_accounts(&self, immune_user_list: Vec<PlatformAddress>) -> Result<()> {
        let immune_user_vec: Vec<Public> = immune_user_list.into_iter().map(PlatformAddress::into_pubkey).collect();

        self.client.register_immune_users(immune_user_vec);
        Ok(())
    }
}
