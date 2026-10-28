from decimal import Decimal
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts" / "pilots"))

from pilot_fast_closers_week1 import (
    AndroidDexJniPlayIntegrityAuditor,
    DatasheetLangGraphOptimizer,
    ElectronCryptoWalletGuard,
    LevelSet,
    OpeningRangeBreakoutReversalEngine,
    ShipStationCryptoEngine,
    SmsMessageJob,
    TwilioMassCampaignEngine,
    USAddress,
)


def test_lx_99173_twilio_50_message_bypass():
    engine = TwilioMassCampaignEngine(
        messaging_service_sids=["MG_POOL_01", "MG_POOL_02", "MG_POOL_03"],
        rate_limit_mps=5.0,
    )
    jobs = [
        SmsMessageJob(contact_id=f"IG_LEAD_{i}", phone_e164=f"+1305555{i:04d}", body="Thanks for clicking our IG ad!")
        for i in range(120)
    ]
    res = engine.dispatch_campaign_batch(jobs)
    assert res["total_input"] == 120
    assert res["delivered_count"] == 120
    assert res["dropped_after_50"] == 0
    assert res["auto_retried_429"] == 1


def test_lx_99346_shipstation_crypto_double_spend_guard_and_clone():
    engine = ShipStationCryptoEngine()
    assert engine.credit_crypto_webhook("user_1", "NP_TX_9001", Decimal("10.00")) is True
    # Duplicate webhook must be rejected idempotently
    assert engine.credit_crypto_webhook("user_1", "NP_TX_9001", Decimal("10.00")) is False

    email, phone = engine.generate_random_contact(seed=7)
    sender = USAddress("Warehouse A", "100 Main St", "Miami", "FL", "33101", "US", email, phone)
    recipient = USAddress("Buyer B", "200 Broadway", "New York", "NY", "10001", "US", email, phone)

    # First $8 label succeeds
    r1 = engine.buy_shipping_label("user_1", "ORD_101", sender, recipient, Decimal("8.00"))
    assert r1["success"] is True
    assert r1["balance_remaining"] == "2.00"

    # Second $8 label on remaining $2 balance must be blocked (no double-spend)
    r2 = engine.buy_shipping_label("user_1", "ORD_102", sender, recipient, Decimal("8.00"))
    assert r2["success"] is False
    assert r2["error"] == "INSUFFICIENT_BALANCE"

    cloned = engine.clone_past_order("ORD_101")
    assert cloned["recipient"].zip_code == "10001"


def test_lx_102286_electron_wallet_bigint_and_1inch_guard():
    # 123.456789 ETH in wei (exceeds IEEE-754 float53 precision if converted naively)
    raw_wei = 123_456_789_123_456_789_123
    formatted = ElectronCryptoWalletGuard.format_token_balance_exact(raw_wei, decimals=18, display_decimals=4)
    assert formatted == "123.4568"

    quote = ElectronCryptoWalletGuard.validate_1inch_swap_quote(
        expected_out_units=1_000_000,
        min_Acceptable_out_units=990_000,
        max_slippage_bps=100,
    )
    assert quote["safe_to_sign"] is True


def test_fl_40791367_opening_range_breakout_and_9_level_reversal():
    level_sets = {
        i: LevelSet(set_id=i, levels=[24100 + idx * 25.0 for idx in range(10)])
        for i in range(1, 10)
    }
    engine = OpeningRangeBreakoutReversalEngine(range_high=24050.0, range_low=24000.0, level_sets=level_sets)

    # Break above Opening Range High -> LONG (Buy Calls)
    s1 = engine.on_futures_tick(24060.0)
    assert s1["side"] == "LONG"
    assert s1["reversal_line"] == 24000.0

    # Reach Level 0 (24100) and Level 1 (24125) -> reversal line trails up to Level 0 (24100)
    s2 = engine.on_futures_tick(24130.0)
    assert s2["highest_level_idx"] == 1
    assert s2["reversal_line"] == 24100.0

    # Price reverses below 24100 -> books profit, flips to SHORT (Buy Puts), advances to Level Set 2
    s3 = engine.on_futures_tick(24090.0)
    assert s3["event"] == "REVERSAL_FLIP_TO_SHORT"
    assert s3["side"] == "SHORT"
    assert s3["set_id"] == 2


def test_fl_40791362_50_page_datasheet_langgraph_router():
    pages = {i: f"Page {i} general mechanical notes and housing diagram." * 20 for i in range(1, 51)}
    pages[14] = "Electrical Characteristics |---| Supply Voltage (Vcc) | Min 3.3 V | Max 5.5 V"
    pages[37] = "Thermal Specifications |---| Operating Temperature | -40 C to +125 C"

    params = [
        {"name": "Supply Voltage", "unit": "V"},
        {"name": "Operating Temperature", "unit": "C"},
    ]
    res = DatasheetLangGraphOptimizer.route_relevant_pages(pages, params, top_k_pages=1)
    assert res["total_pages"] == 50
    assert res["routed_pages_count"] == 2
    assert res["parameter_page_map"]["Supply Voltage"] == [14]
    assert res["parameter_page_map"]["Operating Temperature"] == [37]
    assert res["token_savings_pct"] > 90.0


def test_android_dex_jni_play_integrity_auditor_detects_arm64_svc_and_splits_visibility():
    # Simulated ARM64 prologue + MOV X8, #56 (openat) + SVC #0 (0x01, 0x00, 0x00, 0xd4) + RET
    elf_bytes = b"\xe0\x03\x1f\xaa" + b"\x08\x07\x80\xd2" + b"\x01\x00\x00\xd4" + b"\xc0\x03\x5f\xd6"
    jni_methods = [
        {"name": "nativeCheckEnvironment", "signature": "(Landroid/content/Context;)I", "dynamic": True}
    ]
    root_of_trust = {
        "deviceLocked": False,
        "verifiedBootState": "ORANGE",
        "attestationSecurityLevel": "TrustedEnvironment",
    }
    client_signals = {
        "nonce_mode": "SHA256_PAYLOAD_BOUND",
        "nonce_replay_suspected": True,
    }

    report = AndroidDexJniPlayIntegrityAuditor.audit_native_and_integrity_state(
        elf_code_bytes=elf_bytes,
        jni_registered_methods=jni_methods,
        keystore_root_of_trust=root_of_trust,
        play_integrity_client_signals=client_signals,
    )
    assert report["client_evidence"]["arm64_direct_svc_count"] == 1
    assert report["client_evidence"]["arm64_svc_offsets"] == [8]
    assert report["client_evidence"]["hardware_root_of_trust_intact"] is False
    assert report["meets_strong_integrity_prediction"] is False
    layers = [h["layer"] for h in report["failure_hypotheses"]]
    assert "NATIVE_JNI_ANTI_TAMPER" in layers
    assert "KEYSTORE_ATTESTATION" in layers
    assert "PLAY_INTEGRITY_VERDICT" in layers

