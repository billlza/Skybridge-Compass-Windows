use super::{
    device_discovery_operator_state_error, session_import_operator_state_error,
    session_operator_state_error,
};
use crate::operator_state::OperatorStateError as StateError;
use serde_json::Value;

#[test]
fn rejected_discovery_reports_distinguish_stale_evidence_from_unavailable_state() {
    let directory = "windows_operator_state_directory";
    let snapshot = "windows_agent_owned_discovery_snapshot";
    let freshness = "freshness_window_validation";
    for (cause, code, retryable, gate) in [
        (
            StateError::MissingStateDir,
            "device_discovery_state_dir_missing",
            false,
            directory,
        ),
        (
            StateError::StateDirNotDirectory,
            "device_discovery_state_dir_unavailable",
            false,
            directory,
        ),
        (
            StateError::UnsafePath,
            "device_discovery_state_dir_unsafe",
            false,
            directory,
        ),
        (
            StateError::NearbyDiscoverySnapshotMissing,
            "device_discovery_snapshot_missing",
            false,
            snapshot,
        ),
        (
            StateError::NearbyDiscoveryActiveScanSnapshotMissing,
            "device_discovery_active_scan_snapshot_missing",
            false,
            "windows_agent_owned_discovery_scanner",
        ),
        (
            StateError::NearbyDiscoverySnapshotStale,
            "device_discovery_snapshot_stale",
            true,
            freshness,
        ),
        (
            StateError::NearbyDiscoveryActiveScanSnapshotStale,
            "device_discovery_active_scan_snapshot_stale",
            true,
            freshness,
        ),
        (
            StateError::NearbyDiscoverySnapshotRegistryTooLarge,
            "device_discovery_snapshot_registry_too_large",
            false,
            snapshot,
        ),
        (
            StateError::RegistryLocked,
            "device_discovery_snapshot_registry_unreadable",
            true,
            snapshot,
        ),
        (
            StateError::NearbyDiscoverySnapshotRegistryJson,
            "device_discovery_snapshot_registry_invalid",
            false,
            snapshot,
        ),
        (
            StateError::Clock,
            "device_discovery_clock_invalid",
            true,
            freshness,
        ),
    ] {
        let human = device_discovery_operator_state_error(false, true, true, cause.clone());
        let report = device_discovery_operator_state_error(true, true, true, cause);
        let json: Value = serde_json::from_str(&report).unwrap();
        assert_eq!(json["accepted"], false);
        assert_eq!(json["active_scan_started"], false);
        assert_eq!(json["snapshot_authorizes_connection"], false);
        assert_eq!(json["error"]["code"], code);
        assert_eq!(json["error"]["retryable"], retryable);
        assert_eq!(json["error"]["required_gate"], gate);
        assert_eq!(json["error"]["message"], human);
    }
}

#[test]
fn session_import_and_inventory_report_the_same_failure_without_claiming_a_session() {
    let registry = "windows_agent_owned_session_registry";
    for (cause, code, retryable, gate) in [
        (
            StateError::MissingStateDir,
            "session_state_dir_missing",
            false,
            registry,
        ),
        (
            StateError::StateDirUnavailable,
            "session_state_dir_unavailable",
            false,
            registry,
        ),
        (
            StateError::UnsafePath,
            "session_state_dir_unsafe",
            false,
            registry,
        ),
        (
            StateError::SessionRegistryMissing,
            "session_registry_missing",
            false,
            registry,
        ),
        (
            StateError::SessionRegistryTooLarge,
            "session_registry_too_large",
            false,
            registry,
        ),
        (
            StateError::SessionRegistryRead,
            "session_registry_invalid",
            false,
            registry,
        ),
        (
            StateError::InvalidSessionBinding,
            "session_binding_invalid",
            false,
            "valid_runtime_smoke_appcontrol_evidence",
        ),
        (
            StateError::SessionBindingConflict,
            "session_binding_conflict",
            false,
            registry,
        ),
        (
            StateError::SessionRegistryPersistVerify,
            "session_registry_write_failed",
            true,
            registry,
        ),
        (
            StateError::SessionNotFound,
            "session_not_found",
            false,
            registry,
        ),
        (
            StateError::Clock,
            "session_clock_invalid",
            true,
            "freshness_window_validation",
        ),
        (
            StateError::SessionStale,
            "session_registry_invalid",
            false,
            registry,
        ),
    ] {
        let human = session_import_operator_state_error(false, cause.clone());
        let import: Value =
            serde_json::from_str(&session_import_operator_state_error(true, cause.clone()))
                .unwrap();
        let listing: Value =
            serde_json::from_str(&session_operator_state_error(true, "session.ls", cause)).unwrap();
        assert_eq!(import["session_imported"], false);
        assert_eq!(listing["session_found"], false);
        for json in [import, listing] {
            assert_eq!(json["accepted"], false);
            assert_eq!(json["live_runtime_started"], false);
            assert_eq!(json["error"]["code"], code);
            assert_eq!(json["error"]["message"], human);
            assert_eq!(json["error"]["retryable"], retryable);
            assert_eq!(json["error"]["required_gate"], gate);
        }
    }
}
