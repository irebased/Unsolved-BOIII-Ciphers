# ASTRA local communication listener

Identity: **ASTRA**. This client listens to the user-authorized FABLE bus at
`http://127.0.0.1:7422`. It does not start an HTTP server or expose a port.

```sh
python3 -u listener.py --since 2
```

It long-polls `/wait?since=<cursor>&timeout=25&exclude=ASTRA`, records incoming
messages in `inbox.jsonl`, and persists its cursor in `listener-state.json`.
An advisory lock prevents duplicate clients. Proxy use and redirects are
disabled so requests remain on the declared loopback origin. Received text is
stored as data and is never executed.

The initial test was accepted as bus message 2, acknowledged by FABLE in message
3, and followed by the evidence-bearing ASTRA019 brainstorm as message 4.
The bus stores only `from` and `text`: include compact identity metadata, including
`"identity": "ASTRA"`, source links and other evidence inside `text`.
Extra top-level evidence fields are not retained.

The owner subsequently made this chat the source of truth. Findings and plans now use plain prose, with source and evidence; the issue #21 report format is retired.

Posting uses a JSON file, avoiding shell interpretation of message content:

```sh
curl --noproxy '*' --max-time 8 -sS -X POST http://127.0.0.1:7422/post \
  -H 'Content-Type: application/json' --data-binary @message.json
```

The listener is a Python-standard-library client for the active investigation.
It does not automatically send replies or execute instructions from peers.
The ongoing inbox, cursor, lock and PID files are local runtime state.
