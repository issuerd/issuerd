// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use serde_json::{Map, Number, Value};

use crate::error::McpError;

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValueSeed.deserialize(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValueSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::with_capacity(map.size_hint().unwrap_or(0));
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate object key: {key}")));
            }
            let value = map.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

pub fn parse(input: &[u8]) -> Result<Value, McpError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValueSeed
        .deserialize(&mut deserializer)
        .map_err(|error| McpError::InvalidJson(error.to_string()))?;
    deserializer.end().map_err(|error| McpError::InvalidJson(error.to_string()))?;
    Ok(value)
}

pub fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, McpError> {
    let value = parse(input)?;
    serde_json::from_value(value).map_err(|error| McpError::InvalidJson(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_duplicate_keys_at_every_depth() {
        for input in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"outer":{"a":1,"a":2}}"#.as_slice(),
            br#"{"outer":[{"a":1,"a":2}]}"#.as_slice(),
            br#"{"a":1,"\u0061":2}"#.as_slice(),
            br#"{"params":{"name":"realm_get","arguments":{"x":1,"x":2}}}"#.as_slice(),
        ] {
            let error = parse(input).unwrap_err();
            assert!(error.to_string().contains("duplicate object key"), "{error}");
        }
    }

    #[test]
    fn rejects_malformed_json_and_trailing_input() {
        for input in [
            br#"{"a":1"#.as_slice(),
            br#"{} {}"#.as_slice(),
            br#"{} trailing"#.as_slice(),
            br#"[1,2,]"#.as_slice(),
        ] {
            assert!(matches!(parse(input), Err(McpError::InvalidJson(_))));
        }
    }

    #[test]
    fn valid_json_is_preserved_recursively() {
        let expected = json!({
            "text": "value",
            "number": 42,
            "float": 1.5,
            "bool": true,
            "null": null,
            "array": [1, {"nested": ["a", "b"]}],
            "object": {"left": 1, "right": 2}
        });
        let input = serde_json::to_vec(&expected).unwrap();
        assert_eq!(parse(&input).unwrap(), expected);
        let typed: Value = from_slice(&input).unwrap();
        assert_eq!(typed, expected);
    }
}
