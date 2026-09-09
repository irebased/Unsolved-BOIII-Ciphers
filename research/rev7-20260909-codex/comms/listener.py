#!/usr/bin/env python3
"""ASTRA loopback-only long-poll listener. Incoming text is logged, never executed."""
import argparse
import fcntl
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORIGIN = "http://127.0.0.1:7422"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def timestamp():
    return datetime.now(timezone.utc).isoformat()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", type=int, default=2)
    args = parser.parse_args()
    lock = (HERE / "listener.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("ASTRA listener already running")
    state_file = HERE / "listener-state.json"
    cursor = args.since
    if state_file.exists():
        cursor = max(cursor, json.loads(state_file.read_text())["last_id"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    (HERE / "listener.pid").write_text(str(os.getpid()) + "\n")
    print(json.dumps({"identity": "ASTRA", "listener": "started", "origin": ORIGIN, "since": cursor}), flush=True)
    while True:
        query = urllib.parse.urlencode({"since": cursor, "timeout": 25, "exclude": "ASTRA"})
        try:
            with opener.open(ORIGIN + "/wait?" + query, timeout=35) as response:
                payload = json.load(response)
            messages = payload.get("messages", [])
            for message in messages:
                message_id = int(message["id"])
                if message_id <= cursor:
                    continue
                cursor = message_id
                if message.get("from") == "ASTRA":
                    continue
                record = {"identity": "ASTRA", "received_at": timestamp(), "message": message}
                with (HERE / "inbox.jsonl").open("a") as log:
                    log.write(json.dumps(record, ensure_ascii=False) + "\n")
                print(json.dumps(record, ensure_ascii=False), flush=True)
            cursor = max(cursor, int(payload.get("last_id", cursor)))
            state = {"identity": "ASTRA", "origin": ORIGIN, "last_id": cursor, "last_poll": timestamp(), "pid": os.getpid()}
            temporary = state_file.with_suffix(".tmp")
            temporary.write_text(json.dumps(state, indent=2) + "\n")
            temporary.replace(state_file)
        except (OSError, ValueError, KeyError, urllib.error.URLError) as error:
            record = {"identity": "ASTRA", "at": timestamp(), "listener_error": str(error), "last_id": cursor}
            with (HERE / "listener-errors.jsonl").open("a") as log:
                log.write(json.dumps(record) + "\n")
            print(json.dumps(record), flush=True)
            time.sleep(5)

if __name__ == "__main__":
    main()
