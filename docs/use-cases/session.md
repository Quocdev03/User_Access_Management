# Session Use Cases

All operations require bearer access and global rate limiting.

| ID | Method and path | Contract |
| --- | --- | --- |
| SESSION-LIST | `GET /users/me/sessions` | List unexpired owned sessions; mark the current session by access-token JTI |
| SESSION-REVOKE | `DELETE /users/me/sessions/{id}` | Require ownership, blacklist target JTI fail-closed and revoke/delete the session |
| CLIENT-PROFILE-LIST | `GET /users/me/devices` | List observed client profiles recorded during login |

## Collision and failure rules

- Session ID lookup is scoped to authenticated user.
- Revoke is idempotent only after ownership has been established; it never reveals another user's session.
- `SESSION-REVOKE` records durable `revoked_at`, then blacklists JTI. Redis failure triggers durable invalidate-all compensation and the request fails closed.
- Concurrent refresh/revoke locks the session row; only a non-revoked current refresh hash can rotate.
- Client profile represents a full user-agent observation plus parsed families and recent network observation, not a guaranteed physical device. OS/browser families are not a uniqueness key.
- Session cap is enforced during login by revoking oldest excess sessions and blacklisting their JTI before success is returned.
