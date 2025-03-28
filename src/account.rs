use crate::{
    types::{
        Export, GenericFields, Import, Info, Limits, NatsLimits, Permission, Permissions,
        SigningKey, NO_LIMIT,
    },
    Claim, ClaimType, Claims,
};
use derive_builder::Builder;
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OperatorLimits {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub nats: Option<NatsLimits>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountLimits>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub jetstream: Option<JetStreamLimits>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub tiered_limits: Option<BTreeMap<String, Limits>>,
}

impl Default for OperatorLimits {
    fn default() -> Self {
        Self {
            nats: Some(NatsLimits::default()),
            account: Some(AccountLimits::default()),
            jetstream: None,
            tiered_limits: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct JetStreamLimits {
    #[serde(rename = "mem_storage", skip_serializing_if = "Option::is_none")]
    pub memory_storage: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_storage: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streams: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ack_pending: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_max_stream_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_max_stream_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_required: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exports: Option<i64>,
    #[serde(rename = "wildcards", skip_serializing_if = "Option::is_none")]
    pub wildcard_exports: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disallow_bearer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf: Option<i64>,
}

impl Default for AccountLimits {
    fn default() -> Self {
        Self {
            imports: Some(NO_LIMIT),
            exports: Some(NO_LIMIT),
            wildcard_exports: Some(true),
            disallow_bearer: None,
            conn: Some(NO_LIMIT),
            leaf: Some(NO_LIMIT),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WeightedMapping {
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

type Mapping = BTreeMap<String, Vec<WeightedMapping>>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalAuthorization {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_users: Option<BTreeSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_accounts: Option<BTreeSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xkey: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct MsgTrace {
    #[serde(rename = "dest", skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Builder)]
#[builder(setter(into), default)]
pub struct Account {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports: Option<Vec<Import>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exports: Option<Vec<Export>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<OperatorLimits>,
    //#[serde(skip_serializing_if = "BTreeMap::is_empty")]
    //pub signing_keys: BTreeMap<String, UserScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_keys: Option<IndexSet<SigningKey>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocations: Option<BTreeMap<String, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_permissions: Option<Permissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mappings: Option<Mapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<ExternalAuthorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<MsgTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<Info>,
    #[serde(flatten)]
    pub generic_fields: GenericFields,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            generic_fields: GenericFields {
                claim_type: ClaimType::Account,
                ..Default::default()
            },
            default_permissions: Some(Permissions {
                publish: Permission::default(),
                subscribe: Permission::default(),
                resp: None,
            }),
            limits: Some(OperatorLimits::default()),
            info: None,
            imports: None,
            exports: None,
            signing_keys: None,
            revocations: None,
            mappings: None,
            authorization: None,
            trace: None,
        }
    }
}

impl Claim for Account {
    fn validate() {}
}

impl Account {
    pub fn new_claims(name: String, nkey: String) -> Claims<Account> {
        let account = Self::default();
        let mut claim = Claims::new(account);
        claim.name = Some(name);
        claim.sub = nkey;
        claim
    }
}
