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
    SatelliteMultiOrderCollisionGuard,
    ShipStationCryptoEngine,
    SmsMessageJob,
    TurnkeyHeavyOrderDeliverablePackager,
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


def test_satellite_multi_order_collision_guard_freezes_new_bids_and_auto_withdraws_on_escrow():
    current_13_orders = [
        {"order_id": "ST-MULTIHOPPER", "tier": "TIER_0_PRECOMPLETED_BOUNTY", "post_award_hours": 0.0, "escrow_funded": False},
        {"order_id": "ST-INSIDE-BLOCK", "tier": "TIER_0_PRECOMPLETED_BOUNTY", "post_award_hours": 0.0, "escrow_funded": False},
        {"order_id": "FL-40790593", "tier": "TIER_1_DROP_IN_AUTOMATED", "post_award_hours": 1.0, "escrow_funded": False},
        {"order_id": "FL-40789906", "tier": "TIER_1_DROP_IN_AUTOMATED", "post_award_hours": 0.5, "escrow_funded": False},
        {"order_id": "FL-40789694", "tier": "TIER_1_DROP_IN_AUTOMATED", "post_award_hours": 2.0, "escrow_funded": False},
        {"order_id": "LX-99173", "tier": "TIER_1_DROP_IN_AUTOMATED", "post_award_hours": 1.5, "escrow_funded": False},
        {"order_id": "LX-98738", "tier": "TIER_1_DROP_IN_AUTOMATED", "post_award_hours": 2.0, "escrow_funded": False},
        {"order_id": "LX-101582", "tier": "TIER_1_DROP_IN_AUTOMATED", "post_award_hours": 2.0, "escrow_funded": False},
        {"order_id": "LX-99346", "tier": "TIER_2_HEAVY_CUSTOM_INTEGRATION", "post_award_hours": 14.0, "escrow_funded": False},
        {"order_id": "LX-102286", "tier": "TIER_2_HEAVY_CUSTOM_INTEGRATION", "post_award_hours": 12.0, "escrow_funded": False},
        {"order_id": "LX-105141", "tier": "TIER_2_HEAVY_CUSTOM_INTEGRATION", "post_award_hours": 16.0, "escrow_funded": False},
        {"order_id": "LX-105189", "tier": "TIER_2_HEAVY_CUSTOM_INTEGRATION", "post_award_hours": 8.0, "escrow_funded": False},
        {"order_id": "LX-98546", "tier": "TIER_2_HEAVY_CUSTOM_INTEGRATION", "post_award_hours": 6.0, "escrow_funded": False},
    ]

    # 1. With 11 pending freelance bids (6 Tier-1 + 5 Tier-2), new bids MUST be frozen immediately
    audit = SatelliteMultiOrderCollisionGuard.audit_portfolio_collision_risk(current_13_orders)
    assert audit["total_orders"] == 13
    assert audit["tier_0_count"] == 2
    assert audit["tier_1_fast_count"] == 6
    assert audit["tier_2_heavy_count"] == 5
    assert audit["allow_new_freelance_bids"] is False
    assert audit["operational_directive"] == "FREEZE_NEW_BIDS_AND_PREBUILD_DROP_IN_PACKAGES"

    # 2. The moment 1 heavy order (e.g. LX-105141) locks Escrow, the remaining 4 unfunded heavy offers are flagged for immediate withdrawal
    current_13_orders[10]["escrow_funded"] = True  # LX-105141 funded
    audit_after_award = SatelliteMultiOrderCollisionGuard.audit_portfolio_collision_risk(current_13_orders)
    assert audit_after_award["withdraw_unfunded_heavy_offers"] is True
    assert "LX-99346" in audit_after_award["offers_to_withdraw_on_award"]
    assert "LX-102286" in audit_after_award["offers_to_withdraw_on_award"]
    assert "LX-105141" not in audit_after_award["offers_to_withdraw_on_award"]
    assert audit_after_award["operational_directive"] == "EXECUTE_FUNDED_ESCROW_ONLY_AND_WITHDRAW_HEAVY_QUEUE"


def test_option_a_turnkey_heavy_order_deliverable_packager_reduces_integration_to_under_2_hours():
    # 1. LX-105141 ($500) Turnkey Android Forensic Dossier
    d1 = TurnkeyHeavyOrderDeliverablePackager.build_lx_105141_turnkey_dossier(
        elf_code_bytes=b"\x01\x00\x00\xd4",
        jni_registered_methods=[{"name": "nativeVerify", "signature": "()Z", "dynamic": True}],
        keystore_root_of_trust={"deviceLocked": True, "verifiedBootState": "VERIFIED", "attestationSecurityLevel": "StrongBox"},
        play_integrity_client_signals={"nonce_mode": "SHA256_PAYLOAD_BOUND"},
    )
    assert d1["drop_in_ready"] is True
    assert d1["post_award_hours_remaining"] <= 2.0
    assert "LX-105141" in d1["markdown_report"]

    # 2. LX-99346 ($550) Turnkey Crypto Shipping Package
    engine = ShipStationCryptoEngine()
    email, phone = engine.generate_random_contact(seed=11)
    sender = USAddress("Matrix Labs", "100 Main St", "Austin", "TX", "78701", "US", email, phone)
    recipient = USAddress("Client Ops", "200 Market St", "San Francisco", "CA", "94105", "US", email, phone)
    d2 = TurnkeyHeavyOrderDeliverablePackager.build_lx_99346_turnkey_shipping_package(
        engine=engine,
        user_id="user_opt_a",
        order_id="ORD_OPT_A_1",
        sender=sender,
        recipient=recipient,
        tx_hash="NP_TX_OPT_A",
        paid_usdc=Decimal("25.00"),
        label_cost_usdc=Decimal("10.00"),
    )
    assert d2["drop_in_ready"] is True
    assert d2["post_award_hours_remaining"] <= 2.0
    assert d2["primary_label"]["success"] is True
    assert d2["cloned_label"]["recipient"].zip_code == "94105"

    # 3. LX-102286 ($450) Turnkey Electron Crypto Wallet Package
    d3 = TurnkeyHeavyOrderDeliverablePackager.build_lx_102286_turnkey_wallet_package(
        raw_balance_wei=123_456_789_123_456_789_123,
        decimals=18,
        display_decimals=4,
        expected_out_units=1_000_000,
        min_acceptable_out_units=990_000,
        max_slippage_bps=100,
    )
    assert d3["drop_in_ready"] is True
    assert d3["post_award_hours_remaining"] <= 2.0
    assert d3["formatted_balance"] == "123.4568"
    assert d3["swap_security_audit"]["safe_to_sign"] is True



