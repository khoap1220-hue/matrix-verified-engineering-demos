import pathlib
import sys
import tempfile
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts" / "pilots"))

from pilot_05_system_bug_hunter_sandbox import (
    DefensiveHardeningGuards,
    MatrixStaticBugHunter,
    UpstreamLiveCodeVerifier,
)


def test_static_ast_scanner_detects_cwe22_cwe918_and_cwe502():
    vulnerable_sample = '''
import os
import requests
import torch

def load_user_artifact(base_upload_dir: str, user_file: str, webhook_url: str, model_path: str):
    full_path = os.path.abspath(os.path.join(base_upload_dir, user_file))
    if not full_path.startswith(base_upload_dir):
        raise ValueError("Invalid path")
    resp = requests.get(webhook_url, timeout=5)
    model = torch.load(model_path)
    return resp.status_code, model
'''
    findings = MatrixStaticBugHunter.scan_python_source(vulnerable_sample, filename="sample_ai_service.py")
    rule_ids = [f.rule_id for f in findings]
    assert "MATRIX-AST-CWE22-PREFIX" in rule_ids
    assert "MATRIX-AST-CWE918-SSRF-REDIRECT" in rule_ids
    assert "MATRIX-AST-CWE502-DESERIALIZE" in rule_ids


def test_static_ast_scanner_passes_hardened_code_with_zero_false_positives():
    hardened_sample = '''
import requests
import torch

def load_safe(webhook_url: str, model_path: str):
    resp = requests.get(webhook_url, timeout=5, allow_redirects=False)
    model = torch.load(model_path, weights_only=True)
    return resp.status_code, model
'''
    findings = MatrixStaticBugHunter.scan_python_source(hardened_sample, filename="hardened_ai_service.py")
    assert len(findings) == 0


def test_defensive_path_containment_blocks_sibling_prefix_and_traversal():
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp) / "uploads"
        sibling = pathlib.Path(tmp) / "uploads_secret"
        base.mkdir()
        sibling.mkdir()

        # Valid relative path succeeds
        valid = DefensiveHardeningGuards.safe_resolve_contained_path(base, "models/weights.bin")
        assert valid.is_relative_to(base.resolve())

        # Sibling prefix attack (`../uploads_secret/key.pem`) is blocked even though string starts with `.../uploads`
        with pytest.raises(PermissionError):
            DefensiveHardeningGuards.safe_resolve_contained_path(base, "../uploads_secret/key.pem")


def test_defensive_ssrf_guard_blocks_cloud_metadata_and_pins_public_ip():
    dns_map = {
        "metadata.internal.attacker.tld": ["169.254.169.254"],
        "localhost.alias.tld": ["127.0.0.1"],
        "api.openai.com": ["104.18.7.192"],
    }
    with pytest.raises(PermissionError):
        DefensiveHardeningGuards.validate_and_pin_ssrf_url(
            "http://metadata.internal.attacker.tld/latest/meta-data/",
            mock_dns_resolver=dns_map,
        )
    with pytest.raises(PermissionError):
        DefensiveHardeningGuards.validate_and_pin_ssrf_url(
            "http://localhost.alias.tld:8080/admin",
            mock_dns_resolver=dns_map,
        )

    pinned = DefensiveHardeningGuards.validate_and_pin_ssrf_url(
        "https://api.openai.com/v1/models",
        mock_dns_resolver=dns_map,
    )
    assert pinned["pinned_ip"] == "104.18.7.192"
    assert pinned["allow_redirects"] is False
    assert pinned["headers"] == {"Host": "api.openai.com"}


def test_open_webui_terminals_home_dir_containment_and_admin_path_remediation():
    with tempfile.TemporaryDirectory() as tmp:
        # 1. Verify safe_terminals_home_dir blocks both relative traversal (`../victim`) and absolute reset (`/etc`)
        valid_dir = DefensiveHardeningGuards.safe_terminals_home_dir(tmp, "user-uuid-1234", "abcdef123456")
        assert valid_dir.is_relative_to(pathlib.Path(tmp).resolve())

        with pytest.raises(PermissionError):
            DefensiveHardeningGuards.safe_terminals_home_dir(tmp, "../other_tenant")

        with pytest.raises(PermissionError):
            DefensiveHardeningGuards.safe_terminals_home_dir(tmp, "/etc")

    # 2. Verify terminals.py:138 vs 149 policy_id base_path fix
    res = DefensiveHardeningGuards.is_admin_terminal_path_blocked(
        connection_url="http://terminals-orchestrator:8000",
        policy_id="sandbox-policy",
        safe_path="api/v1/policies",
    )
    assert res["upstream_blocked"] is False  # Upstream misses `/p/sandbox-policy/api/v1/policies`
    assert res["patched_blocked"] is True    # Patched check blocks `/p/sandbox-policy/api/v1/policies`


def test_verbatim_upstream_execution_open_webui_terminals_cwe22():
    proof = UpstreamLiveCodeVerifier.verify_open_webui_terminals_cwe22_execution()
    assert proof["escaped_bind_before_patch"] is True
    assert proof["victim_deleted_before_patch"] is True
    assert proof["blocked_by_patch"] is True
    assert proof["victim_intact_after_patch"] is True
    assert proof["verified_100_percent"] is True
    assert "--- a/terminals/backends/docker.py" in str(proof["unified_patch"])


def test_verbatim_upstream_execution_open_webui_openai_passthrough_acl():
    proof = UpstreamLiveCodeVerifier.verify_open_webui_openai_passthrough_acl_execution()
    assert proof["chat_completions_blocked"] is True
    assert proof["upstream_proxy_allowed_unauthorized"] is True
    assert proof["patched_proxy_blocked_unauthorized"] is True
    assert proof["verified_100_percent"] is True
    assert "--- a/backend/open_webui/routers/openai.py" in str(proof["unified_patch"])


def test_bug_bounty_target_roi_gate_rejects_unfunded_or_non_default_targets():
    # Rejects open-webui on legacy Huntr (closed portal + non-default config)
    rejected = UpstreamLiveCodeVerifier.evaluate_bug_bounty_target_roi_gate(
        target_repo="open-webui/open-webui",
        submission_portal_open=False,
        active_escrow_pool_usd=0.0,
        allows_automated_code_audit=True,
        exploitable_in_default_config=False,
        requires_internal_api_key_or_admin=False,
        verified_by_verbatim_execution=True,
    )
    assert rejected["approved_for_deep_hunt"] is False
    assert "NO_ACTIVE_ESCROW_OR_PORTAL_CLOSED" in rejected["rejection_reasons"]
    assert "NON_DEFAULT_CONFIG_PREREQUISITE" in rejected["rejection_reasons"]

    # Approves funded smart-contract/protocol audit target with default-config execution proof
    approved = UpstreamLiveCodeVerifier.evaluate_bug_bounty_target_roi_gate(
        target_repo="sherlock-audit/2026-active-contest",
        submission_portal_open=True,
        active_escrow_pool_usd=105000.0,
        allows_automated_code_audit=True,
        exploitable_in_default_config=True,
        requires_internal_api_key_or_admin=False,
        verified_by_verbatim_execution=True,
    )
    assert approved["approved_for_deep_hunt"] is True
    assert approved["estimated_commercial_value_usd"] == 105000.0



