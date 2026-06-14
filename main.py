import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

import requests
import stripe
from fastapi import FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI()

DATABASE_PATH = os.environ.get("DATABASE_PATH", "stripe_events.db")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")


def init_db() -> None:
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS stripe_events (
                stripe_event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                created_timestamp INTEGER,
                payload TEXT NOT NULL,
                discord_status TEXT,
                processed_at TEXT NOT NULL,
                discord_sent_at TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def parse_utc_timestamp(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def format_discord_message(event: stripe.Event) -> dict[str, Any]:
    data = event.data.object if event.data and event.data.object else {}
    event_type = event.type
    event_id = event.id
    created = event.created
    object_type = data.get("object", "unknown")

    fields = [
        {"name": "Event Type", "value": event_type, "inline": True},
        {"name": "Stripe Event ID", "value": event_id, "inline": True},
        {"name": "Object Type", "value": object_type, "inline": True},
        {"name": "Created", "value": parse_utc_timestamp(created), "inline": True},
    ]

    amount = data.get("amount")
    currency = data.get("currency")
    amount_received = data.get("amount_received")
    amount_captured = data.get("amount_captured")
    customer = data.get("customer")
    email = data.get("receipt_email")
    description = data.get("description")
    status = data.get("status")
    payment_method = data.get("payment_method")

    if amount is not None:
        fields.append(
            {"name": "Amount", "value": f"{amount} {currency or ''}".strip(), "inline": True}
        )
    if amount_received is not None:
        fields.append({"name": "Amount Received", "value": str(amount_received), "inline": True})
    if amount_captured is not None:
        fields.append({"name": "Amount Captured", "value": str(amount_captured), "inline": True})
    if customer:
        fields.append({"name": "Customer", "value": str(customer), "inline": True})
    if email:
        fields.append({"name": "Receipt Email", "value": email, "inline": True})
    if description:
        fields.append({"name": "Description", "value": description, "inline": False})
    if status:
        fields.append({"name": "Status", "value": status, "inline": True})
    if payment_method:
        fields.append({"name": "Payment Method", "value": str(payment_method), "inline": True})

    return {
        "embeds": [
            {
                "title": f"Stripe Event: {event_type}",
                "color": 0x635bff,
                "fields": fields,
                "footer": {"text": "Stripe Webhook"},
            }
        ]
    }


def send_discord(event: stripe.Event) -> bool:
    if not DISCORD_WEBHOOK_URL:
        return False
    payload = format_discord_message(event)
    try:
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        return response.status_code in (200, 204)
    except requests.RequestException:
        return False


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    if not STRIPE_WEBHOOK_SECRET:
        return JSONResponse(status_code=500, content={"detail": "Stripe webhook secret not configured"})

    payload = await request.body()
    payload_str = payload.decode("utf-8")

    try:
        event = stripe.Webhook.construct_event(payload_str, stripe_signature, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return JSONResponse(status_code=400, content={"detail": "Invalid payload"})
    except stripe.error.SignatureVerificationError:
        return JSONResponse(status_code=400, content={"detail": "Invalid signature"})

    event_id = event.id
    event_type = event.type
    created_timestamp = event.created
    full_payload = json.dumps(event.to_dict(), separators=(",", ":"))
    processed_at = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DATABASE_PATH)
    try:
        cursor = conn.execute(
            "SELECT 1 FROM stripe_events WHERE stripe_event_id = ?",
            (event_id,),
        )
        exists = cursor.fetchone() is not None

        if not exists:
            conn.execute(
                """
                INSERT INTO stripe_events
                (stripe_event_id, event_type, created_timestamp, payload, discord_status, processed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_id, event_type, created_timestamp, full_payload, "pending", processed_at),
            )
            conn.commit()

        discord_ok = send_discord(event)
        discord_status = "success" if discord_ok else "failure"
        discord_sent_at = datetime.now(timezone.utc).isoformat()

        conn.execute(
            "UPDATE stripe_events SET discord_status = ?, discord_sent_at = ? WHERE stripe_event_id = ?",
            (discord_status, discord_sent_at, event_id),
        )
        conn.commit()
    finally:
        conn.close()

    return Response(status_code=200)
