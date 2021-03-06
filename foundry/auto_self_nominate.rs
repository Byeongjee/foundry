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

use crate::config::load_config;
use ccore::{AccountProvider, AccountProviderError, BlockId, ConsensusClient, Encodable, UnverifiedTransaction};
use ckey::PlatformAddress;
use ckey::{Ed25519Public as Public, Signature};
use ckeystore::DecryptedAccount;
use clap::ArgMatches;
use cstate::{Banned, Candidates, Jail};
use ctypes::transaction::Action::SelfNominate;
use ctypes::transaction::Transaction;
use primitives::{Bytes, H256};
use std::convert::TryInto;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const NEED_NOMINATION_UNDER_TERM_LEFT: u64 = 3;
#[derive(Clone)]
struct SelfSigner {
    account_provider: Arc<AccountProvider>,
    signer: Option<Public>,
    decrypted_account: Option<DecryptedAccount>,
}
impl SelfSigner {
    pub fn new(ap: Arc<AccountProvider>, pubkey: Public) -> Self {
        let public = {
            let account =
                ap.get_unlocked_account(&pubkey).expect("The public key must be registered in AccountProvider");
            account.public().expect("Cannot get public from account")
        };
        Self {
            account_provider: ap,
            signer: Some(public),
            decrypted_account: None,
        }
    }

    pub fn sign_ed25519(&self, hash: H256) -> Result<Signature, AccountProviderError> {
        let pubkey = self.signer.unwrap_or_else(Default::default);
        let result = match &self.decrypted_account {
            Some(account) => account.sign(&hash)?,
            None => {
                let account = self.account_provider.get_unlocked_account(&pubkey)?;
                account.sign(&hash)?
            }
        };
        Ok(result)
    }

    /// Public Key of signer.
    pub fn pubkey(&self) -> Option<&Public> {
        self.signer.as_ref()
    }
}

pub struct AutoSelfNomination {
    client: Arc<dyn ConsensusClient>,
    signer: SelfSigner,
}

impl AutoSelfNomination {
    pub fn new(client: Arc<dyn ConsensusClient>, ap: Arc<AccountProvider>, pubkey: Public) -> Arc<Self> {
        Arc::new(Self {
            client,
            signer: SelfSigner::new(ap, pubkey),
        })
    }

    pub fn send_self_nominate_transaction(&self, matches: &ArgMatches) {
        let config = load_config(matches).unwrap();
        let account_address = config.mining.engine_signer.unwrap();
        let default_metadata = config.mining.self_nomination_metadata.unwrap();
        let target_deposit = config.mining.self_target_deposit.unwrap();
        let interval = config.mining.self_nomination_interval.unwrap();
        let self_client = self.client.clone();
        let self_signer = self.signer.clone();
        thread::Builder::new()
            .name("Auto Self Nomination".to_string())
            .spawn(move || loop {
                AutoSelfNomination::send(
                    &self_client,
                    &self_signer,
                    &account_address,
                    &default_metadata,
                    target_deposit,
                );
                thread::sleep(Duration::from_millis(interval));
            })
            .unwrap();
    }

    fn send(
        client: &Arc<dyn ConsensusClient>,
        signer: &SelfSigner,
        account_address: &PlatformAddress,
        metadata: &str,
        targetdep: u64,
    ) {
        let metabytes = metadata.rlp_bytes();
        let mut dep = targetdep;
        let pubkey = account_address.pubkey();
        let block_id = BlockId::Latest;
        let state = client.state_at(block_id).unwrap();
        let current_term = client.current_term_id(block_id).unwrap();
        let banned = Banned::load_from_state(&state).unwrap();
        if banned.is_banned(pubkey) {
            cwarn!(ENGINE, "Account is banned");
            return
        }
        let jailed = Jail::load_from_state(&state).unwrap();
        if jailed.get_prisoner(&pubkey).is_some() {
            let prisoner = jailed.get_prisoner(&pubkey).unwrap();

            if prisoner.custody_until <= (current_term) {
                cwarn!(ENGINE, "Account is still in custody");
                return
            }
        }
        let candidate = Candidates::load_from_state(&state).unwrap();
        if candidate.get_candidate(&pubkey).is_some() {
            let candidate_need_nomination = candidate.get_candidate(&pubkey).unwrap();
            if candidate_need_nomination.nomination_ends_at + NEED_NOMINATION_UNDER_TERM_LEFT <= current_term {
                cdebug!(
                    ENGINE,
                    "No need self nominate. nomination_ends_at: {}, current_term: {}",
                    candidate_need_nomination.nomination_ends_at,
                    current_term
                );
                return
            }
            if candidate_need_nomination.deposit.lt(&targetdep) {
                dep = targetdep.min(targetdep);
            } else {
                dep = 0 as u64;
            }
        }

        AutoSelfNomination::self_nomination_transaction(&client, &signer, dep, metabytes);
    }

    fn self_nomination_transaction(
        client: &Arc<dyn ConsensusClient>,
        signer: &SelfSigner,
        deposit: u64,
        metadata: Bytes,
    ) {
        let network_id = client.network_id();
        let seq = match signer.pubkey() {
            Some(pubkey) => client.latest_seq(pubkey),
            None => {
                cwarn!(ENGINE, "Signer was not assigned");
                return
            }
        };
        let selfnominate = SelfNominate {
            deposit,
            metadata,
        };
        let tx = Transaction {
            seq,
            fee: 0,
            network_id,
            action: selfnominate,
        };

        let signature = match signer.sign_ed25519(*tx.hash()) {
            Ok(signature) => signature,
            Err(e) => {
                cerror!(ENGINE, "Could not sign the message:{}", e);
                return
            }
        };
        let signer_public = *signer.pubkey().expect("Signer must be initialized");
        let unverified = UnverifiedTransaction::new(tx, signature, signer_public);
        let signed = unverified.try_into().expect("secret is valid so it's recoverable");

        match client.queue_own_transaction(signed) {
            Ok(_) => {
                cinfo!(ENGINE, "Send self nominate transaction");
            }
            Err(e) => {
                cerror!(ENGINE, "Failed to queue self nominate transaction: {}", e);
            }
        }
    }
}
