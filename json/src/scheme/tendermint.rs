// Copyright 2018-2019 Kodebox, Inc.
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

use crate::uint::Uint;
use ckey::{Address, BlsPublic, PlatformAddress};
use std::collections::HashMap;

/// Tendermint params deserialization.
#[derive(Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TendermintParams {
    /// Valid validators.
    pub validators: Vec<(Address, BlsPublic)>,
    /// Propose step timeout in milliseconds.
    pub timeout_propose: Option<Uint>,
    /// Propose step timeout delta in milliseconds.
    pub timeout_propose_delta: Option<Uint>,
    /// Prevote step timeout in milliseconds.
    pub timeout_prevote: Option<Uint>,
    /// Prevote step timeout delta in milliseconds.
    pub timeout_prevote_delta: Option<Uint>,
    /// Precommit step timeout in milliseconds.
    pub timeout_precommit: Option<Uint>,
    /// Precommit step timeout delta in milliseconds.
    pub timeout_precommit_delta: Option<Uint>,
    /// Commit step timeout in milliseconds.
    pub timeout_commit: Option<Uint>,
    /// Reward per block.
    pub block_reward: Option<Uint>,
    /// How much tokens are distributed at Genesis?
    pub genesis_stakes: Option<HashMap<PlatformAddress, u64>>,
    /// allowed past time gap in milliseconds.
    pub allowed_past_timegap: Option<Uint>,
    /// allowed future time gap in milliseconds.
    pub allowed_future_timegap: Option<Uint>,
}

/// Tendermint engine deserialization.
#[derive(Debug, PartialEq, Deserialize)]
pub struct Tendermint {
    pub params: TendermintParams,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ckey::{Address, BlsPublic};
    use serde_json;

    use super::Tendermint;

    #[test]
    fn tendermint_deserialization() {
        let s = r#"{
            "params": {
                "validators": [["0xc1f7057e36205fe711c1d645c6c037d10e40e0a8",
                "0x81fc91b26e2bb60e4f1936d63ec3d540507578d38ee3800a691de957419f2f455ce074cb6ef2e179434cf900c6eac9d80af3ac0c7b1b56f118826f33272b8f2cdd62cde37505e2fa3f3f8c89740513c5c055099c02cbed96d26ecef84d224768"]]
            }
        }"#;

        let deserialized: Tendermint = serde_json::from_str(s).unwrap();
        let address = Address::from_str("c1f7057e36205fe711c1d645c6c037d10e40e0a8").unwrap();
        let bls_public = BlsPublic::from_str("81fc91b26e2bb60e4f1936d63ec3d540507578d38ee3800a691de957419f2f455ce074cb6ef2e179434cf900c6eac9d80af3ac0c7b1b56f118826f33272b8f2cdd62cde37505e2fa3f3f8c89740513c5c055099c02cbed96d26ecef84d224768").unwrap();
        let validators = vec![(address, bls_public)];
        assert_eq!(deserialized.params.validators, validators);
    }
}
