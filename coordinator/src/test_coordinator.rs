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

use super::context::SubStorageAccess;
use super::validator::*;
use ctypes::{CompactValidatorSet, ConsensusParams};
use std::sync::atomic::{AtomicUsize, Ordering};

// Coordinator dedicated for mempool and miner testing
// Only check_transactions, remove_transactions,
pub struct TestCoordinator {
    validator_set: CompactValidatorSet,
    consensus_params: ConsensusParams,
    body_count: AtomicUsize,
    body_size: AtomicUsize,
}

impl TestCoordinator {
    pub fn initialize_chain(&self, app_state: String) -> (CompactValidatorSet, ConsensusParams) {
        unimplemented!()
    }
}
impl Default for TestCoordinator {
    fn default() -> Self {
        Self {
            validator_set: Default::default(),
            consensus_params: ConsensusParams::default_for_test(),
            body_count: AtomicUsize::new(0),
            body_size: AtomicUsize::new(0),
        }
    }
}

impl BlockExecutor for TestCoordinator {
    fn open_block(&self, _context: &mut dyn SubStorageAccess, _header: &Header, _verified_crime: &[VerifiedCrime]) {
        self.body_count.store(0, Ordering::SeqCst);
        self.body_size.store(0, Ordering::SeqCst);
    }

    fn execute_transactions(&self, _context: &mut dyn SubStorageAccess, transactions: &[Transaction]) {
        self.body_count.fetch_add(transactions.len(), Ordering::SeqCst);
        let body_size: usize = transactions.iter().map(|tx| tx.size()).sum();
        self.body_size.fetch_add(body_size, Ordering::SeqCst);
    }

    fn close_block(&self, context: &mut dyn SubStorageAccess) -> BlockOutcome {
        let is_success = self.body_size.load(Ordering::SeqCst) > self.consensus_params.max_body_size();
        BlockOutcome {
            is_success,
            updated_validator_set: self.validator_set.clone(),
            updated_consensus_params: self.consensus_params,
            transaction_results: (0..self.body_count.load(Ordering::SeqCst))
                .map(|_| TransactionExecutionOutcome {
                    events: Vec::new(),
                })
                .collect(),
            events: Vec::new(),
        }
    }
}

impl TxFilter for TestCoordinator {
    fn check_transaction(&self, transaction: &Transaction) -> Result<(), ErrorCode> {
        if transaction.size() > self.consensus_params.max_body_size() {
            Err(1)
        } else {
            Ok(())
        }
    }

    fn fetch_transactions_for_block<'a>(
        &self,
        transactions: Vec<&'a TransactionWithMetadata>,
    ) -> Vec<TransactionWithGas<'a>> {
        transactions
            .into_iter()
            .map(|tx_with_metadata| TransactionWithGas {
                tx_with_metadata,
                gas: 0,
            })
            .collect()
    }

    fn remove_transactions<'a>(
        &self,
        transactions: Vec<&'a TransactionWithMetadata>,
        memory_limit: Option<usize>,
        size_limit: Option<usize>,
    ) -> (Vec<&'a TransactionWithMetadata>, Vec<&'a TransactionWithMetadata>) {
        let invalid = Vec::new();
        let mut memory = 0;
        let mut size = 0;
        let low_priority = transactions
            .into_iter()
            .skip_while(|tx| {
                memory += tx.size();
                size += 1;
                memory <= memory_limit.unwrap_or(usize::max_value()) && size <= size_limit.unwrap_or(usize::max_value())
            })
            .collect();
        (invalid, low_priority)
    }
}
