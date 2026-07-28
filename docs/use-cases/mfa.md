# MFA Use Cases

**Status:** implemented. The six operations below are part of the current
41-operation public contract.

| ID | Method and path | Actor | Contract |
| --- | --- | --- | --- |
| MFA-LOGIN-VERIFY | `POST /auth/mfa/login/verify` | Public with opaque challenge | Verify TOTP or one-time recovery code and issue one session |
| MFA-SETUP | `POST /auth/mfa/setup` | Bearer | Verify current password, persist an encrypted pending secret and return enrollment material |
| MFA-CONFIRM | `POST /auth/mfa/confirm` | Bearer | Verify pending TOTP, enable MFA and return recovery codes once |
| MFA-DISABLE | `POST /auth/mfa/disable` | Bearer | Verify current password plus TOTP/recovery code, then disable MFA |
| MFA-STATUS | `GET /auth/mfa/status` | Bearer | Return enabled state and remaining recovery-code count; never return a secret |
| MFA-RECOVERY-REGENERATE | `POST /auth/mfa/recovery/regenerate` | Bearer | Verify current password plus MFA and replace all recovery codes |

## Login journey

```text
AUTH-LOGIN credential/account check
→ if MFA disabled: issue session
→ if MFA enabled: create Redis challenge only
→ MFA-LOGIN-VERIFY atomically claims the challenge
→ verify factor and recheck locked account/auth_version/MFA state
→ conditionally consume TOTP step or recovery code
→ issue session and atomically finish the claimed challenge
```

Only the claimant can finish or release a challenge. An invalid factor increments
the challenge attempt count and releases it; the final failed attempt deletes it.
A system failure releases the claim so a retry can proceed. If Redis cannot confirm
challenge consumption after a session was committed, durable auth invalidation
compensates by increasing `auth_version` and deleting sessions.

## Dependencies and transaction boundaries

| Use case | MySQL transaction | Redis/network after transaction |
| --- | --- | --- |
| MFA-LOGIN-VERIFY | Lock account → MFA row; recheck auth version/state; consume factor; update login state; create session and audit | Claim before MySQL; finish/release after commit; blacklist any evicted JTI |
| MFA-SETUP | Lock account → MFA row; create/replace pending enrollment and audit | TOTP generation and AES-GCM encryption happen before the transaction |
| MFA-CONFIRM | Lock account → MFA row; enable TOTP, replace recovery hashes, increment `auth_version`, delete sessions and audit | None |
| MFA-DISABLE | Lock account → MFA row; consume factor, delete MFA, increment `auth_version`, delete sessions and audit | Password/TOTP verification happens before the transaction and snapshots are rechecked under lock |
| MFA-STATUS | Read MFA row and unused recovery count | None |
| MFA-RECOVERY-REGENERATE | Lock account → MFA row; consume factor, replace hashes, increment `auth_version`, delete sessions and audit | Password/TOTP verification happens before the transaction and snapshots are rechecked under lock |

All MySQL calls inside a transaction use `txCtx`. Redis, bcrypt and TOTP work stay
outside the MySQL transaction. Lock order is account row before MFA row.

## Security, concurrency and failure behavior

- TOTP allows a documented ±1 time-step window.
- Secret uses AES-GCM and a configured key version; missing production key fails startup.
- Challenge includes user ID, auth version, attempts and TTL.
- Redis Lua atomically creates, claims, finishes or releases the challenge; `GET` + `DEL` is forbidden.
- Two concurrent valid verifications produce at most one session.
- A TOTP time step is globally one-time per user through a conditional MySQL update.
- Recovery codes are random, shown once, hashed at rest and consumed with a conditional update.
- Setup/confirm/disable/regenerate serialize on the account/MFA rows and append audit in the transaction.
- Confirm, disable and recovery regeneration invalidate all existing sessions in the same transaction as the MFA mutation.
- Redis failure is fail-closed. No session is issued before MFA verification.
- No secret, TOTP, recovery code or challenge payload appears in logs.
