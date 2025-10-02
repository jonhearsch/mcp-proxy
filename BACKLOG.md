# Engineering Backlog

SRE improvements and technical debt items for MCP Proxy Server.

## Critical Priority

### Logging Improvements
- [ ] Add structured logging (JSON format) for better log aggregation/parsing
- [ ] Include correlation IDs for request tracing
- [ ] Log startup configuration (redacting secrets) for debugging
- [ ] Add metrics/counters for restart attempts, config reloads, errors

### Observability Gaps
- [ ] Add Prometheus metrics endpoint for restart count, uptime, config reload success/failure
- [ ] Implement health check readiness vs liveness distinction (k8s best practice)
- [ ] Add startup/readiness probes - server should not report healthy before proxy is created
- [ ] Add `/metrics` endpoint exposing key SLIs

### Configuration Validation
- [ ] Validate new config before reload - currently crashes if bad config loaded
- [ ] Add config schema validation with detailed error messages
- [ ] Support config dry-run mode for testing
- [ ] Validate environment expansion/secrets exist before startup

### Resource Management
- [ ] Add resource limits on child MCP processes (memory, CPU)
- [ ] Implement cleanup of zombie child processes if MCP servers crash
- [ ] Add timeout on server shutdown - could hang indefinitely
- [ ] Add context managers for proper cleanup

### Security Hardening
- [ ] Make host/port configurable via env vars instead of hardcoded 0.0.0.0:8080
- [ ] Add TLS/mTLS support for production deployments
- [ ] Implement secret management (vault, env var validation)
- [ ] Consider readonly filesystem in container

## Medium Priority

### Operational Excellence
- [ ] Add SIGHUP for reload instead of requiring file watch (standard pattern)
- [ ] Implement circuit breaker for failing upstream MCP servers
- [ ] Add startup timeout - fail fast if server doesn't start in N seconds
- [ ] Support multiple config sources (file, etcd, consul)

### Restart Logic Refinement
- [ ] Improve restart limit - 10 is too low, consider time-based window (10 restarts/hour)
- [ ] Add circuit breaker pattern - after N failures, enter degraded mode
- [ ] Add restart backoff jitter to prevent thundering herd
- [ ] Expose restart history via API for debugging

### Docker/K8s Optimization
- [ ] Replace curl-based health check with native Python HTTP check
- [ ] Add prestop hook for graceful termination
- [ ] Support PID 1 signal handling properly (tini/dumb-init)
- [ ] Add memory limits in Dockerfile

### Error Handling
- [ ] Replace `os._exit(42)` with proper shutdown event - too aggressive, bypasses cleanup
- [ ] Add exception classification (retryable vs non-retryable)
- [ ] Implement alerting thresholds (e.g., 3 crashes/min = page)
- [ ] Add better error context in logs

### Testing & Reliability
- [ ] Add integration tests for config reload
- [ ] Add chaos testing (kill -9, network partition)
- [ ] Test signal handling edge cases
- [ ] Add performance tests for proxy overhead

## Low Priority

### Code Quality
- [ ] Extract hardcoded values to constants (port, host, timeouts)
- [ ] Add type hints throughout (currently partial)
- [ ] Consider dataclasses for config instead of raw dict
- [ ] Add CLI arguments support (not just env vars)

### Monitoring Enhancement
- [ ] Add request/response logging at proxy level
- [ ] Track per-upstream-server metrics (success rate, latency)
- [ ] Add trace context propagation (OpenTelemetry)
- [ ] Export logs to stdout in JSON for log aggregation

## Completed
<!-- Move items here as they are completed -->

---

## Notes

**Priority Recommendations:**
1. Config validation before reload (prevents crashes on bad config)
2. Proper health/readiness endpoints (k8s compatibility)
3. Structured logging with metrics (operational visibility)
4. Better shutdown handling - replace `os._exit()` (resource cleanup)

**Context:**
These recommendations come from Sr SRE review focusing on production reliability, observability, and operational excellence.
