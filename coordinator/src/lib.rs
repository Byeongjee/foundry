#![allow(dead_code, unused_variables)]
use context::SubStorageAccess;
use std::unimplemented;
use validator::*;

pub mod context;
pub mod validator;

/// The `Coordinator` encapsulates all the logic for a Foundry application.
///
/// It assembles modules and feeds them various events from the underlying
/// consensus engine.

#[derive(Default)]
pub struct Coordinator {}

impl validator::Validator for Coordinator {
    fn initialize_chain(&self) -> ConsensusParams {
        unimplemented!()
    }

    fn open_block(&self, context: &mut dyn SubStorageAccess, header: &Header, evidences: &[Evidence]) {
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
    ) -> Vec<&'a TransactionWithGas> {
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
