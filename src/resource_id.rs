//! Stable sandbox resource identity derived from a parent run and optional server key.
//!
//! The v1 namespace and length-prefixed SHA-256 encoding are durable identity contracts.

use crate::error::ReedeError;
use crate::isolation::SandboxId;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const RESOURCE_NAMESPACE_V1: &[u8] = b"reede/mcp-server-sandbox/v1";
const MAX_SERVER_KEY_BYTES: usize = 256;

/// Derive a resource ID from the canonical parent run ID and optional stable server key.
///
/// `None` preserves legacy identity exactly. A present key is used byte-for-byte: it is not
/// trimmed, case-folded or otherwise normalized. This is a bounded transport check, not a
/// manifest-name policy. Callers still own declaration validation and resource-spec equality.
pub fn derive_sandbox_id(
    parent_run_id: Uuid,
    server_key: Option<&str>,
) -> Result<SandboxId, ReedeError> {
    let Some(server_key) = server_key else {
        return Ok(SandboxId(parent_run_id));
    };

    let key_bytes = server_key.as_bytes();
    if key_bytes.is_empty()
        || key_bytes.len() > MAX_SERVER_KEY_BYTES
        || key_bytes.iter().any(u8::is_ascii_control)
    {
        return Err(ReedeError::SpecValidationFailed {
            reason: "sandbox server identity key is invalid".to_string(),
        });
    }

    let mut hasher = Sha256::new();
    update_length_prefixed(&mut hasher, RESOURCE_NAMESPACE_V1);
    update_length_prefixed(&mut hasher, parent_run_id.as_bytes());
    update_length_prefixed(&mut hasher, key_bytes);

    let digest = hasher.finalize();
    let mut resource_uuid = [0u8; 16];
    resource_uuid.copy_from_slice(&digest[..16]);
    Ok(SandboxId(Uuid::from_bytes(resource_uuid)))
}

fn update_length_prefixed(hasher: &mut Sha256, field: &[u8]) {
    // All current fields are fixed or bounded well below u64::MAX.
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_key_preserves_nil_and_non_nil_parent_ids() {
        let nil = Uuid::nil();
        let parent = Uuid::from_u128(0x00112233445566778899aabbccddeeff);
        assert_eq!(derive_sandbox_id(nil, None).unwrap(), SandboxId(nil));
        assert_eq!(derive_sandbox_id(parent, None).unwrap(), SandboxId(parent));
    }

    #[test]
    fn keyed_identity_matches_fixed_v1_golden_vector() {
        let parent = Uuid::from_u128(0x00112233445566778899aabbccddeeff);
        assert_eq!(
            derive_sandbox_id(parent, Some("server-one"))
                .unwrap()
                .0
                .as_bytes(),
            &[
                0x0b, 0x0b, 0x63, 0xf6, 0xfb, 0x36, 0x9a, 0xae, 0x3f, 0xeb, 0x6b, 0x3b, 0x91, 0x6e,
                0x72, 0xa3,
            ]
        );
    }

    #[test]
    fn parent_and_key_both_partition_resource_identity() {
        let parent = Uuid::from_u128(0x00112233445566778899aabbccddeeff);
        let other_parent = Uuid::from_u128(0x10112233445566778899aabbccddeeff);
        let base = derive_sandbox_id(parent, Some("server-one")).unwrap();
        assert_ne!(
            base,
            derive_sandbox_id(other_parent, Some("server-one")).unwrap()
        );
        assert_ne!(base, derive_sandbox_id(parent, Some("server-two")).unwrap());
    }

    #[test]
    fn key_bytes_are_exact_and_not_normalized() {
        let parent = Uuid::from_u128(7);
        let exact = derive_sandbox_id(parent, Some("Server-One")).unwrap();
        assert_ne!(
            exact,
            derive_sandbox_id(parent, Some("server-one")).unwrap()
        );
        assert_ne!(
            exact,
            derive_sandbox_id(parent, Some(" Server-One")).unwrap()
        );
        assert_ne!(
            exact,
            derive_sandbox_id(parent, Some("Server-One ")).unwrap()
        );
    }

    #[test]
    fn key_bounds_and_ascii_controls_fail_with_a_generic_error() {
        let parent = Uuid::from_u128(8);
        let max_ascii_key = "x".repeat(MAX_SERVER_KEY_BYTES);
        assert!(derive_sandbox_id(parent, Some(&max_ascii_key)).is_ok());

        for bad_key in [
            String::new(),
            "x".repeat(MAX_SERVER_KEY_BYTES + 1),
            "secret\nkey".to_string(),
            "secret\u{7f}key".to_string(),
        ] {
            let error = derive_sandbox_id(parent, Some(&bad_key)).unwrap_err();
            assert!(matches!(error, ReedeError::SpecValidationFailed { .. }));
            assert_eq!(
                error.to_string(),
                "Spec validation failed: sandbox server identity key is invalid"
            );
        }
    }

    #[test]
    fn multibyte_keys_are_bounded_by_utf8_bytes_without_panicking() {
        let parent = Uuid::from_u128(9);
        let multibyte_prefix = "é".repeat((MAX_SERVER_KEY_BYTES - 2) / 2);
        let within_limit = format!("{multibyte_prefix}ab");
        let over_limit = format!("{multibyte_prefix}abc");
        assert_eq!(within_limit.len(), MAX_SERVER_KEY_BYTES);
        assert_eq!(over_limit.len(), MAX_SERVER_KEY_BYTES + 1);
        assert!(derive_sandbox_id(parent, Some(&within_limit)).is_ok());
        assert!(derive_sandbox_id(parent, Some(&over_limit)).is_err());
    }
}
