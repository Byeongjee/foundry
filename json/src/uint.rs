// Copyright 2015-2017 Parity Technologies (UK) Ltd.
// Copyright 2020 Kodebox, Inc.
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

use primitives::U256;
use serde::de::{Error, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Lenient uint json deserialization for test json files.
#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Uint(pub U256);

impl From<Uint> for U256 {
    fn from(f: Uint) -> Self {
        f.0
    }
}

impl From<Uint> for u64 {
    fn from(f: Uint) -> Self {
        Self::from(f.0)
    }
}

impl From<Uint> for u32 {
    fn from(f: Uint) -> Self {
        Self::from(f.0)
    }
}

impl From<Uint> for u16 {
    fn from(f: Uint) -> Self {
        u64::from(f.0) as u16
    }
}

impl From<Uint> for u8 {
    fn from(f: Uint) -> Self {
        u64::from(f.0) as u8
    }
}

impl From<Uint> for usize {
    fn from(f: Uint) -> Self {
        // TODO: clean it after util conversions refactored.
        u64::from(f.0) as usize
    }
}

impl From<u64> for Uint {
    fn from(f: u64) -> Self {
        Uint(f.into())
    }
}

impl From<u32> for Uint {
    fn from(f: u32) -> Self {
        Uint(f.into())
    }
}

impl From<u16> for Uint {
    fn from(f: u16) -> Self {
        Uint(f.into())
    }
}

impl From<u8> for Uint {
    fn from(f: u8) -> Self {
        Uint(f.into())
    }
}

impl From<usize> for Uint {
    fn from(f: usize) -> Self {
        Uint(f.into())
    }
}

// This impl is to support expressions like `0.into()`
impl From<i32> for Uint {
    fn from(f: i32) -> Self {
        Uint(f.into())
    }
}

impl<'a> Deserialize<'a> for Uint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>, {
        deserializer.deserialize_any(UintVisitor)
    }
}

impl Serialize for Uint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        self.0.serialize(serializer)
    }
}

struct UintVisitor;

impl<'a> Visitor<'a> for UintVisitor {
    type Value = Uint;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a hex encoded or decimal uint")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: Error, {
        Ok(Uint(U256::from(value)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: Error, {
        let value = match value.len() {
            0 => U256::from(0),
            2 if value.starts_with("0x") => U256::from(0),
            _ if value.starts_with("0x") => U256::from_str(&value[2..])
                .map_err(|e| Error::custom(format!("Invalid hex value {}: {}", value, e).as_str()))?,
            _ => U256::from_dec_str(value)
                .map_err(|e| Error::custom(format!("Invalid decimal value {}: {:?}", value, e).as_str()))?,
        };

        Ok(Uint(value))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: Error, {
        self.visit_str(value.as_ref())
    }
}

pub fn validate_non_zero<'de, D>(d: D) -> Result<Uint, D::Error>
where
    D: Deserializer<'de>, {
    let value = Uint::deserialize(d)?;

    if value == Uint(U256::from(0)) {
        return Err(Error::invalid_value(Unexpected::Unsigned(value.into()), &"a non-zero value"))
    }

    Ok(value)
}

pub fn validate_optional_non_zero<'de, D>(d: D) -> Result<Option<Uint>, D::Error>
where
    D: Deserializer<'de>, {
    let value: Option<Uint> = Option::deserialize(d)?;

    if let Some(value) = value {
        if value == Uint(U256::from(0)) {
            return Err(Error::invalid_value(Unexpected::Unsigned(value.into()), &"a non-zero value"))
        }
    }

    Ok(value)
}

#[cfg(test)]
mod test {
    use super::Uint;
    use primitives::U256;

    #[test]
    fn uint_deserialization() {
        let s = r#"["0xa", "10", "", "0x", 0, "0xffffffffffffffff"]"#;
        let deserialized: Vec<Uint> = serde_json::from_str(s).unwrap();
        assert_eq!(deserialized, vec![
            Uint(U256::from(10)),
            Uint(U256::from(10)),
            Uint(U256::from(0)),
            Uint(U256::from(0)),
            Uint(U256::from(0)),
            u64::MAX.into(),
        ]);
    }

    #[test]
    fn uint_into() {
        assert_eq!(U256::from(10), Uint(U256::from(10)).into());
    }

    #[test]
    fn uint_serialization() {
        let v: Vec<Uint> = vec![0.into(), 1.into(), 100.into(), u64::MAX.into()];
        let serialized = serde_json::to_string(&v).unwrap();
        assert_eq!(r#"["0x0","0x1","0x64","0xffffffffffffffff"]"#, serialized);
    }
}
