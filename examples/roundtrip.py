import json
import secrets
from pathlib import Path

from mcp_event_subscriptions import open_envelope, seal

record = json.loads(Path(__file__).with_name("subscription.json").read_text())
keys = {"k1": secrets.token_bytes(32)}
context = {
    "server": "https://mcp.example.com",
    "tenant": "project_demo",
    "resource": record["id"],
}
token = seal(record, keys, active_key="k1", context=context)
assert open_envelope(token, keys, expected_context=context) == record
print("Subscription sealed and recovered successfully (secrets omitted).")
