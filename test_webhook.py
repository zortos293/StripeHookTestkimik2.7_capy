import json
import os
import sqlite3
import time

import stripe
from fastapi.testclient import TestClient

from main import DATABASE_PATH, app, init_db

os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_test_secret"

client = TestClient(app)

def clear_db():
    init_db()
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("DELETE FROM stripe_events")
    conn.commit()
    conn.close()


def make_payload():
    return {
        "id": "evt_test_123",
        "object": "event",
        "type": "payment_intent.succeeded",
        "created": 1710000000,
        "data": {
            "object": {
                "object": "payment_intent",
                "id": "pi_test_123",
                "amount": 2000,
                "currency": "usd",
                "status": "succeeded",
                "receipt_email": "test@example.com",
                "customer": "cus_test_123",
                "payment_method": "pm_test_123",
                "description": "Test payment",
            }
        },
    }


def sign(payload, secret, timestamp=None):
    if timestamp is None:
        timestamp = int(time.time())
    body = json.dumps(payload, separators=(",", ":"))
    signed_payload = f"{timestamp}.{body}"
    return stripe.WebhookSignature._compute_signature(signed_payload, secret)


def test_invalid_signature():
    clear_db()
    payload = make_payload()
    response = client.post(
        "/stripe/webhook",
        data=json.dumps(payload, separators=(",", ":")),
        headers={"Stripe-Signature": "t=123,v1=invalid"},
    )
    assert response.status_code == 400


def test_valid_event_saved_and_discord_recorded(monkeypatch):
    clear_db()
    calls = []

    def fake_send_discord(event):
        calls.append(event.id)
        return True

    import main

    monkeypatch.setattr(main, "send_discord", fake_send_discord)

    payload = make_payload()
    ts = int(time.time())
    sig = sign(payload, "whsec_test_secret", ts)
    response = client.post(
        "/stripe/webhook",
        data=json.dumps(payload, separators=(",", ":")),
        headers={"Stripe-Signature": f"t={ts},v1={sig}"},
    )
    assert response.status_code == 200

    conn = sqlite3.connect(DATABASE_PATH)
    row = conn.execute(
        "SELECT stripe_event_id, event_type, discord_status FROM stripe_events"
    ).fetchone()
    conn.close()
    assert row[0] == "evt_test_123"
    assert row[1] == "payment_intent.succeeded"
    assert row[2] == "success"


def test_idempotent_duplicate(monkeypatch):
    clear_db()
    calls = []

    def fake_send_discord(event):
        calls.append(event.id)
        return True

    import main

    monkeypatch.setattr(main, "send_discord", fake_send_discord)

    payload = make_payload()
    ts = int(time.time())
    sig = sign(payload, "whsec_test_secret", ts)
    headers = {"Stripe-Signature": f"t={ts},v1={sig}"}
    body = json.dumps(payload, separators=(",", ":"))

    r1 = client.post("/stripe/webhook", data=body, headers=headers)
    r2 = client.post("/stripe/webhook", data=body, headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 200

    conn = sqlite3.connect(DATABASE_PATH)
    count = conn.execute(
        "SELECT COUNT(*) FROM stripe_events WHERE stripe_event_id = ?",
        ("evt_test_123",),
    ).fetchone()[0]
    conn.close()
    assert count == 1


def test_discord_failure_still_saves(monkeypatch):
    clear_db()

    def fake_send_discord(event):
        return False

    import main

    monkeypatch.setattr(main, "send_discord", fake_send_discord)

    payload = make_payload()
    payload["id"] = "evt_test_456"
    ts = int(time.time())
    sig = sign(payload, "whsec_test_secret", ts)
    response = client.post(
        "/stripe/webhook",
        data=json.dumps(payload, separators=(",", ":")),
        headers={"Stripe-Signature": f"t={ts},v1={sig}"},
    )
    assert response.status_code == 200

    conn = sqlite3.connect(DATABASE_PATH)
    row = conn.execute(
        "SELECT discord_status FROM stripe_events WHERE stripe_event_id = ?",
        ("evt_test_456",),
    ).fetchone()
    conn.close()
    assert row[0] == "failure"


if __name__ == "__main__":
    test_invalid_signature()
    print("invalid signature ok")
    import pytest
    pytest.main([__file__, "-v"])
