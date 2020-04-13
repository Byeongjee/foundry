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

#![allow(dead_code, unused_variables)]
use context::SubStorageAccess;
use ctypes::{CompactValidatorSet, ConsensusParams};
use std::unimplemented;
use validator::*;

pub mod context;
pub mod test_coordinator;
pub mod validator;

/// The `Coordinator` encapsulates all the logic for a Foundry application.
///
/// It assembles modules and feeds them various events from the underlying
/// consensus engine.

#[derive(Default)]
pub struct Coordinator {}

impl validator::Validator for Coordinator {
    fn initialize_chain(&self, app_state: String) -> (CompactValidatorSet, ConsensusParams) {
        unimplemented!()
    }

    fn open_block(&self, context: &mut dyn SubStorageAccess, header: &Header, verified_crime: &[VerifiedCrime]) {
        unimplemented!()
    }

    fn execute_transactions(&self, context: &mut dyn SubStorageAccess, transactions: &[Transaction]) {
        unimplemented!()
    }

    fn close_block(&self, context: &mut dyn SubStorageAccess) -> BlockOutcome {
        unimplemented!()
    }

    fn check_transaction(&self, transaction: &Transaction) -> Result<(), ErrorCode> {
        unimplemented!()
    }

    fn fetch_transactions_for_block<'a>(
        &self,
        transactions: Vec<&'a TransactionWithMetadata>,
    ) -> Vec<TransactionWithGas<'a>> {
        unimplemented!()
    }

    fn remove_transactions<'a>(
        &self,
        transactions: Vec<&'a TransactionWithMetadata>,
        memory_limit: Option<usize>,
        size_limit: Option<usize>,
    ) -> (Vec<&'a TransactionWithMetadata>, Vec<&'a TransactionWithMetadata>) {
        unimplemented!()
    }
}

impl Coordinator {}

pub struct Builder<C: context::Context> {
    context: C,
}

impl<C: context::Context> Builder<C> {
    fn create<CTX: context::Context>(ctx: CTX) -> Builder<CTX> {
        Builder {
            context: ctx,
        }
    }

    fn build(self) -> Coordinator {
        Coordinator {}
    }
}
