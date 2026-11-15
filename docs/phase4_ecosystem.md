# Payload-bound ecosystem adapters

These are framework-neutral helpers, not certified native plugins for every release of MCP, LangChain, Portkey, CrewAI, Composio or Activepieces. Test the actual framework lifecycle in deployment.

Register exact operator ToolRoutes and permitted parameter names. EcosystemGuard snapshots input and sends the exact immutable canonical JSON via execute_payload. Use TenantClient(NexusClient(...), account, scoped_token) against an enterprise-configured daemon. Provider/broker keys never enter the agent process. The server independently checks the current role policy, action, exact endpoint, parameter names and payload hash. Raw IPC cannot bypass this gate.

LangChainToolGuard.ainvoke and the compatibility before_invoke name both EXECUTE the remote operation and return its receipt. Never run a second local tool body afterwards. PortkeyGuardrail.before_request also performs the broker operation: do not forward again. Custom gateways must use the broker result as execution result and disable secondary forwarding.

MCP tools/call, CrewAI, Composio and Activepieces helpers use the same execution path. Unknown tools, invalid routes and credential/URL parameters fail before dispatch with safe fixed errors. Partial/Failed cleanup and unsuccessful provider HTTP statuses are errors, not successful tool results.

Receipts correlate endpoint, body hash and original idempotency key. Cached duplicates carry replayed=true and duplicate_status=409 while preserving original transport_status. This metadata is not an HTTP 409 from the provider. Changed payloads under one key fail before redispatch. Pending/receipt capacities are bounded and reject new work when full. Durable server Redis claims remain authoritative across client restarts.

Portkey error paths drop their own body reference and raise sanitized errors outside decoder exception contexts, avoiding JSONDecodeError.doc retention through chained exceptions. Caller-owned immutable Python objects are not guaranteed erased; never capture secret locals in exception logs. Framework callbacks must not independently dispatch after this adapter already executed.

See enterprise_runbooks.md for configuration, policy-bound tokens, persistent claims, checkpoint retention and release gates. Fake providers and Reference* stores are models, not real network/HA evidence. Regression tests cover malformed JSON, mutation, cleanup/provider failures, cache conflicts/capacity and cancellation budgets.

