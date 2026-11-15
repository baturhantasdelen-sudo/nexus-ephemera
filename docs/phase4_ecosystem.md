# Phase 4 ecosystem adapters

These adapters sit in `nexus_ephemera.ecosystem`. They do not fetch or hold the broker secret. A tool name selects an operator `ToolRoute`. The route's endpoint is the only URL sent to `NexusClient.execute`. Call parameters cannot replace that URL.

The binding digest on the receipt is not a MAC and not mTLS. The daemon computes the HMAC over the payload hash, endpoint, idempotency key, and timestamp. The Python process never sees that key.

## MCP

`handle_mcp_message` answers `initialize`, `tools/list`, and `tools/call`. A tool call's `arguments` are canonicalized, hashed, and passed to the local broker. The JSON-RPC result includes `seal_report` in both the text content and the `nexus` object. An unknown tool or a non-strict URL becomes JSON-RPC `-32003` (`TargetDenied`) and does not call the broker. The same idempotency key returns the cached receipt with `replayed` true and `duplicate_status` 409. `transport_status` remains the status on that cached receipt. The broker does not submit the call to the provider again.

## LangChain

`LangChainToolGuard.before_invoke` runs before the tool body. The body may run only after `seal_report` is `retained` or `complete`. The tool input is a mapping of declared parameters. A string input, an extra field, or a credential field is rejected. The wrapper does not import LangChain and does not accept an API key.

## Portkey

`PortkeyGuardrail.before_request` compares the upstream URL to the registry. A different host, a query string, or a fragment raises `TargetDenied` before `execute`. The body must be the exact canonical payload bytes. Whitespace or a reordered document is `Malformed` and is not forwarded.

## CrewAI, Composio, Activepieces

`crewai_tool_call`, `composio_action`, and `activepieces_step` are the same guard. Parameter names such as `api_key`, `token`, `secret`, `endpoint`, and `url` are rejected and are not copied into the error text. A second identical call returns the cached receipt and sets `duplicate_status` to 409. The same key with a changed parameter is `IdempotencyConflict` and does not dispatch again.

`ProviderEdge.submit` is the reference provider status: the first key returns 204 and a duplicate returns 409. The guard does not call it on replay. A counting broker used in tests records that the provider accepted the key once.

The daemon proof is `tests/ecosystem_mcp_receipt.rs`. It checks the HMAC header, `SealReport::Retained`, a cached replay with one dispatch, an idempotency conflict, and `TargetDenied` for an off-allowlist or query/fragment URL.
