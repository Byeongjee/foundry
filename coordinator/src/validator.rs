use std::any::Any;

use ckey::Public;
use ctypes::header::Header;

/// A `Validator` receives requests from the underlying consensus engine
/// and performs validation of blocks and Txes.
///
///

pub type Bytes = Vec<u8>;

pub type VoteWeight = u64;

pub struct Event {
    pub key: &'static str,
    pub value: Bytes,
}

pub struct ValidatorInfo {
    weight: VoteWeight,
    pubkey: Public,
}

pub struct ConsensusParams {
    /// Validators' public keys with their voting powers.
    pub validators: Vec<ValidatorInfo>,
    // Note: This code is copied from json/src/tendermint.rs
    /// Propose step timeout in milliseconds.
    pub timeout_propose: Option<u64>,
    /// Propose step timeout delta in milliseconds.
    pub timeout_propose_delta: Option<u64>,
    /// Prevote step timeout in milliseconds.
    pub timeout_prevote: Option<u64>,
    /// Prevote step timeout delta in milliseconds.
    pub timeout_prevote_delta: Option<u64>,
    /// Precommit step timeout in milliseconds.
    pub timeout_precommit: Option<u64>,
    /// Precommit step timeout delta in milliseconds.
    pub timeout_precommit_delta: Option<u64>,
    /// Commit step timeout in milliseconds.
    pub timeout_commit: Option<u64>,
    /// Reward per block.
    pub block_reward: Option<u64>,
    /// allowed past time gap in milliseconds.
    pub allowed_past_timegap: Option<u64>,
    /// allowed future time gap in milliseconds.
    pub allowed_future_timegap: Option<u64>,
}

/// A decoded transaction.
pub struct Transaction<'a> {
    tx_type: &'a str,
    body: &'a dyn Any,
}

impl Transaction<'_> {
    fn tx_type(&self) -> &str {
        self.tx_type
    }

    fn body<T: 'static>(&self) -> Option<&T> {
        self.body.downcast_ref()
    }
}

pub enum Evidence {
    DoubleVote, // Should import and use DoubleVote type defined in tendermint module?
}

pub struct TransactionExecutionOutcome {
    is_success: bool,
    events: Vec<Event>,
}

pub struct TransactionCheckOutcome {
    is_success: bool,
    events: Vec<Event>,
}

pub struct BlockOutcome {
    block_hash: Bytes,
    updated_consensus_params: ConsensusParams,
    transaction_results: Vec<TransactionExecutionOutcome>,
    events: Vec<Event>,
}

pub trait Validator {
    fn initialize_chain() -> ConsensusParams;
    fn execute_block(header: Header, transactions: &[Transaction], evidences: &[Evidence]) -> BlockOutcome;
    fn check_transaction(transaction: &Transaction) -> TransactionCheckOutcome;
}
