// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const CDN_PUBLISH_REQUESTED_EVENT_TYPE: &str = "cdn_publish_requested";
pub const CDN_PUBLISH_EVENT_SCHEMA_VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnPublishRequestedEvent {
    #[serde(rename = "eventType")]
    pub event_type: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobKey")]
    pub job_key: String,
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "publicationCursor")]
    pub publication_cursor: i64,
    #[serde(rename = "rootDid")]
    pub root_did: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CdnPublishRequestedEventInput {
    pub job_key: String,
    pub resource_did: String,
    pub package_version: String,
    pub publication_cursor: i64,
    pub root_did: String,
    pub package_hash: String,
    pub did_document_hash: String,
    pub metadata_hash: String,
    pub created_at: DateTime<Utc>,
}

impl CdnPublishRequestedEvent {
    pub fn new(input: CdnPublishRequestedEventInput) -> Self {
        Self {
            event_type: CDN_PUBLISH_REQUESTED_EVENT_TYPE.to_owned(),
            schema_version: CDN_PUBLISH_EVENT_SCHEMA_VERSION.to_owned(),
            job_key: input.job_key,
            resource_did: input.resource_did,
            package_version: input.package_version,
            publication_cursor: input.publication_cursor,
            root_did: input.root_did,
            package_hash: input.package_hash,
            did_document_hash: input.did_document_hash,
            metadata_hash: input.metadata_hash,
            created_at: input.created_at,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.event_type != CDN_PUBLISH_REQUESTED_EVENT_TYPE {
            return Err("unsupported_cdn_publish_event_type".to_owned());
        }
        if self.schema_version != CDN_PUBLISH_EVENT_SCHEMA_VERSION {
            return Err("unsupported_cdn_publish_event_schema".to_owned());
        }
        if self.job_key.trim().is_empty() {
            return Err("empty_job_key".to_owned());
        }
        if self.resource_did.trim().is_empty() {
            return Err("empty_resource_did".to_owned());
        }
        if self.package_version.trim().is_empty() {
            return Err("empty_package_version".to_owned());
        }
        if self.publication_cursor <= 0 {
            return Err("invalid_publication_cursor".to_owned());
        }
        if self.root_did.trim().is_empty() {
            return Err("empty_root_did".to_owned());
        }
        if self.package_hash.trim().is_empty() {
            return Err("empty_package_hash".to_owned());
        }
        if self.did_document_hash.trim().is_empty() {
            return Err("empty_did_document_hash".to_owned());
        }
        if self.metadata_hash.trim().is_empty() {
            return Err("empty_metadata_hash".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_cdn_publish_event_shape() {
        let event = sample_event();
        assert!(event.validate().is_ok());
    }

    #[test]
    fn rejects_empty_or_invalid_event_fields() {
        let mut event = sample_event();
        event.publication_cursor = 0;
        assert_eq!(event.validate().unwrap_err(), "invalid_publication_cursor");
        event.publication_cursor = 1;
        event.schema_version = "2".to_owned();
        assert_eq!(
            event.validate().unwrap_err(),
            "unsupported_cdn_publish_event_schema"
        );
    }

    fn sample_event() -> CdnPublishRequestedEvent {
        CdnPublishRequestedEvent::new(CdnPublishRequestedEventInput {
            job_key: "did:oan:AGUS:test:1.0.0".to_owned(),
            resource_did: "did:oan:AGUS:test".to_owned(),
            package_version: "1.0.0".to_owned(),
            publication_cursor: 7,
            root_did: "did:oan:AGRT:root".to_owned(),
            package_hash: "sha256:package".to_owned(),
            did_document_hash: "sha256:document".to_owned(),
            metadata_hash: "sha256:metadata".to_owned(),
            created_at: Utc::now(),
        })
    }
}
