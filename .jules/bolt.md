# Bolt's Journal

## 2024-04-30 - Context Cancellation vs Natively Enforced Timeout in Dialer
**Learning:** In Go, creating a `context.WithTimeout` in a high-frequency loop (like thousands of TCP connection attempts per second) is an expensive operation that results in significant timer allocations. Since `net.Dialer` already accepts a `Timeout` field which limits the connection natively without needing a separate timeout context per connection, using the root context instead of a localized timeout context drastically increases performance. Using `net.JoinHostPort` instead of `fmt.Sprintf` for IP and port formatting also slightly speeds up string interpolation and reduces overhead.
**Action:** Always prefer setting the underlying struct configurations (like `Timeout` in `net.Dialer`) instead of creating localized contexts, and avoid `fmt.Sprintf` for simple string concatenations.
