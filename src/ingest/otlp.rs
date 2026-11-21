//! The slice of OTLP/trace messages `reede serve` reads, as prost messages (protobuf) that are
//! also serde types (OTLP JSON). Field numbers follow opentelemetry-proto v1 trace.proto.
//!
//! The serde form doubles as the stored, hashed span form (`spans/<seq>.json`): camelCase keys,
//! ids as lowercase hex, 64-bit integers as decimal strings, every field always present. Fields
//! this slice does not model (for example `flags`, dropped counts) are dropped on decode and are
//! not sealed.

use base64::Engine;
use prost::Message;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod hex_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// OTLP JSON bytes values are base64.
mod b64 {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        base64::engine::general_purpose::STANDARD
            .decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)
    }
}

/// Doubles: JSON has no NaN or infinities (serde_json would write null, so different spans
/// could share a summary). They are written as the strings "NaN", "Infinity", "-Infinity",
/// which OTLP JSON also accepts on input.
mod f64_json {
    use super::*;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Num {
        Num(f64),
        Text(String),
    }
    pub fn serialize<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
        if v.is_nan() {
            s.serialize_str("NaN")
        } else if *v == f64::INFINITY {
            s.serialize_str("Infinity")
        } else if *v == f64::NEG_INFINITY {
            s.serialize_str("-Infinity")
        } else {
            s.serialize_f64(*v)
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
        match Num::deserialize(d)? {
            Num::Num(n) => Ok(n),
            Num::Text(t) => match t.as_str() {
                "NaN" => Ok(f64::NAN),
                "Infinity" => Ok(f64::INFINITY),
                "-Infinity" => Ok(f64::NEG_INFINITY),
                other => other.parse().map_err(serde::de::Error::custom),
            },
        }
    }
}

/// OTLP JSON writes 64-bit integers as strings but accepts numbers too.
mod int_str {
    use super::*;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Int<T> {
        Num(T),
        Text(String),
    }
    pub fn serialize<T: ToString, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, T, D>(d: D) -> Result<T, D::Error>
    where
        T: std::str::FromStr + Deserialize<'de>,
        T::Err: std::fmt::Display,
        D: Deserializer<'de>,
    {
        match Int::<T>::deserialize(d)? {
            Int::Num(n) => Ok(n),
            Int::Text(t) => t.parse().map_err(serde::de::Error::custom),
        }
    }
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportTraceServiceRequest {
    #[prost(message, repeated, tag = "1")]
    pub resource_spans: Vec<ResourceSpans>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ResourceSpans {
    #[prost(message, optional, tag = "1")]
    pub resource: Option<Resource>,
    #[prost(message, repeated, tag = "2")]
    pub scope_spans: Vec<ScopeSpans>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Resource {
    #[prost(message, repeated, tag = "1")]
    pub attributes: Vec<KeyValue>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScopeSpans {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<Scope>,
    #[prost(message, repeated, tag = "2")]
    pub spans: Vec<Span>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Scope {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub version: String,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Span {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "hex_bytes")]
    pub trace_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "hex_bytes")]
    pub span_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub trace_state: String,
    #[prost(bytes = "vec", tag = "4")]
    #[serde(with = "hex_bytes")]
    pub parent_span_id: Vec<u8>,
    #[prost(string, tag = "5")]
    pub name: String,
    #[prost(int32, tag = "6")]
    pub kind: i32,
    #[prost(fixed64, tag = "7")]
    #[serde(with = "int_str")]
    pub start_time_unix_nano: u64,
    #[prost(fixed64, tag = "8")]
    #[serde(with = "int_str")]
    pub end_time_unix_nano: u64,
    #[prost(message, repeated, tag = "9")]
    pub attributes: Vec<KeyValue>,
    #[prost(message, repeated, tag = "11")]
    pub events: Vec<Event>,
    #[prost(message, repeated, tag = "13")]
    pub links: Vec<Link>,
    #[prost(message, optional, tag = "15")]
    pub status: Option<Status>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Event {
    #[prost(fixed64, tag = "1")]
    #[serde(with = "int_str")]
    pub time_unix_nano: u64,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(message, repeated, tag = "3")]
    pub attributes: Vec<KeyValue>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Link {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "hex_bytes")]
    pub trace_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "hex_bytes")]
    pub span_id: Vec<u8>,
    #[prost(message, repeated, tag = "4")]
    pub attributes: Vec<KeyValue>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Status {
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(int32, tag = "3")]
    pub code: i32,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KeyValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(message, optional, tag = "2")]
    pub value: Option<AnyValue>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AnyValue {
    #[prost(oneof = "Value", tags = "1, 2, 3, 4, 5, 6, 7")]
    #[serde(flatten)]
    pub value: Option<Value>,
}

#[derive(Clone, PartialEq, prost::Oneof, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Value {
    #[prost(string, tag = "1")]
    StringValue(String),
    #[prost(bool, tag = "2")]
    BoolValue(bool),
    #[prost(int64, tag = "3")]
    IntValue(#[serde(with = "int_str")] i64),
    #[prost(double, tag = "4")]
    DoubleValue(#[serde(with = "f64_json")] f64),
    #[prost(message, tag = "5")]
    ArrayValue(ArrayValue),
    #[prost(message, tag = "6")]
    KvlistValue(KeyValueList),
    #[prost(bytes = "vec", tag = "7")]
    BytesValue(#[serde(with = "b64")] Vec<u8>),
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ArrayValue {
    #[prost(message, repeated, tag = "1")]
    pub values: Vec<AnyValue>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KeyValueList {
    #[prost(message, repeated, tag = "1")]
    pub values: Vec<KeyValue>,
}

/// One span as sealed: the span plus the resource and scope it arrived under, so the stored
/// file is self-contained. This is exactly what `spans/<seq>.json` holds and what is hashed.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedSpan {
    pub resource: Vec<KeyValue>,
    pub scope: Option<Scope>,
    pub span: Span,
}

/// Bounds a host applies to a decoded request BEFORE [`ExportTraceServiceRequest::into_spans`],
/// which copies each resource and scope into every span of it.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Spans in the whole request.
    pub max_spans: usize,
    /// One string or bytes attribute value, in bytes.
    pub max_attr_value: usize,
    /// One span's own JSON size (attributes, events, links), in bytes.
    pub max_span_bytes: usize,
    /// Sum over spans of resource + scope + span JSON size: what `into_spans` would hold.
    pub max_expanded_bytes: usize,
}

fn value_max_len(v: &AnyValue) -> usize {
    match &v.value {
        Some(Value::StringValue(s)) => s.len(),
        Some(Value::BytesValue(b)) => b.len(),
        Some(Value::ArrayValue(a)) => a.values.iter().map(value_max_len).max().unwrap_or(0),
        Some(Value::KvlistValue(l)) => kvs_max_len(&l.values),
        _ => 0,
    }
}

fn kvs_max_len(kvs: &[KeyValue]) -> usize {
    kvs.iter()
        .map(|kv| kv.key.len().max(kv.value.as_ref().map_or(0, value_max_len)))
        .max()
        .unwrap_or(0)
}

fn json_len<T: Serialize>(v: &T) -> usize {
    serde_json::to_vec(v).map_or(usize::MAX, |b| b.len())
}

impl ExportTraceServiceRequest {
    /// Refuse a request that would expand past `limits`. Cheap: one pass, no span copies.
    /// The error text is safe to return to the client.
    pub fn check_limits(&self, limits: &Limits) -> Result<(), String> {
        let spans: usize = self
            .resource_spans
            .iter()
            .flat_map(|r| &r.scope_spans)
            .map(|s| s.spans.len())
            .sum();
        if spans > limits.max_spans {
            return Err(format!(
                "too many spans in one request ({spans}, limit {})",
                limits.max_spans
            ));
        }
        let mut expanded = 0usize;
        for rs in &self.resource_spans {
            let res_attrs = rs.resource.as_ref().map_or(&[][..], |r| &r.attributes[..]);
            if kvs_max_len(res_attrs) > limits.max_attr_value {
                return Err(format!(
                    "a resource attribute exceeds {} bytes",
                    limits.max_attr_value
                ));
            }
            let res_len = json_len(&res_attrs);
            for ss in &rs.scope_spans {
                let scope_len = json_len(&ss.scope);
                for span in &ss.spans {
                    let attr_max = [
                        kvs_max_len(&span.attributes),
                        span.events
                            .iter()
                            .map(|e| kvs_max_len(&e.attributes))
                            .max()
                            .unwrap_or(0),
                        span.links
                            .iter()
                            .map(|l| kvs_max_len(&l.attributes))
                            .max()
                            .unwrap_or(0),
                    ]
                    .into_iter()
                    .max()
                    .unwrap_or(0);
                    if attr_max > limits.max_attr_value {
                        return Err(format!(
                            "a span attribute exceeds {} bytes",
                            limits.max_attr_value
                        ));
                    }
                    let own = json_len(span);
                    if own > limits.max_span_bytes {
                        return Err(format!("a span exceeds {} bytes", limits.max_span_bytes));
                    }
                    expanded = expanded
                        .saturating_add(res_len)
                        .saturating_add(scope_len)
                        .saturating_add(own);
                    if expanded > limits.max_expanded_bytes {
                        return Err(format!(
                            "request would expand past {} bytes once resource and scope are copied into each span",
                            limits.max_expanded_bytes
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn into_spans(self) -> Vec<SealedSpan> {
        let mut out = Vec::new();
        for rs in self.resource_spans {
            let resource = rs.resource.map(|r| r.attributes).unwrap_or_default();
            for ss in rs.scope_spans {
                for span in ss.spans {
                    out.push(SealedSpan {
                        resource: resource.clone(),
                        scope: ss.scope.clone(),
                        span,
                    });
                }
            }
        }
        out
    }
}

impl Span {
    /// Ids must be the OTLP sizes and non-zero; anything else is a malformed export.
    pub fn validate(&self) -> Result<(), String> {
        if self.trace_id.len() != 16 || self.trace_id.iter().all(|b| *b == 0) {
            return Err("span trace_id must be 16 non-zero bytes".into());
        }
        if self.span_id.len() != 8 || self.span_id.iter().all(|b| *b == 0) {
            return Err("span span_id must be 8 non-zero bytes".into());
        }
        if !matches!(self.parent_span_id.len(), 0 | 8) {
            return Err("span parent_span_id must be empty or 8 bytes".into());
        }
        for l in &self.links {
            if l.trace_id.len() != 16 || l.span_id.len() != 8 {
                return Err("link trace_id must be 16 bytes and span_id 8 bytes".into());
            }
        }
        Ok(())
    }

    fn int_attr(&self, key: &str) -> Option<u64> {
        let kv = self.attributes.iter().find(|kv| kv.key == key)?;
        match kv.value.as_ref()?.value.as_ref()? {
            Value::IntValue(n) => u64::try_from(*n).ok(),
            Value::DoubleValue(d)
                if d.is_finite() && *d >= 0.0 && d.fract() == 0.0 && *d <= u32::MAX as f64 =>
            {
                Some(*d as u64)
            }
            _ => None,
        }
    }

    /// `gen_ai.usage.input_tokens + gen_ai.usage.output_tokens` when present, else 0.
    pub fn tokens(&self) -> u32 {
        let total = self
            .int_attr("gen_ai.usage.input_tokens")
            .unwrap_or(0)
            .saturating_add(self.int_attr("gen_ai.usage.output_tokens").unwrap_or(0));
        total.min(u32::MAX as u64) as u32
    }
}
