# Windows audio authorization across process restart

Status: implementation contract under review. Product offline restart recovery is not enabled. The native continuity and file-commit experiments establish only the specific boundaries listed below.

## Current product boundaries

`AccountSessionCoordinator.HydrateFromStoreCoreAsync` requires live account verification on launch. A temporary authentication failure retains the protected credentials but clears the published account identity. `AccountAudioAuthorization` and `AudioAccountMembershipProvider` are process-local. A valid cached membership can be reused within its original lifetime in that process; parsing saved JWT claims cannot substitute for previously verified audio authority after restart.

`SessionStore` currently writes a schema-1 credential record and deletes it on clear. Its atomic file replacement has no revision check, durable login identifier or audio checkpoint. By contrast, `QPeriaptTrustedStateStore` already uses a separate file lease and compare-and-swap for its own policy record. That policy record must keep its existing owner and format; it is not an audio grant store.

The shared `AtomicSessionFileCommitter` now requests Windows write-through replacement after callers flush and close a same-directory temporary file. It preserves a native error as a failed commit. Atomic replacement alone does not arbitrate stale writers or record revocation.

## Recovery contract

A future canonical protected account record must bind credentials, one durable login identifier, a mutation revision and audio checkpoint state. These fields cannot be committed independently. A fresh login creates a new login identifier; credential rotation and process restart retain the same identifier only when their identity continuity has been verified.

A restored membership must retain its original evidence ID, account authority/subject/tenant, both exact device protocol identities, issue time and both expiry anchors. The same-logon seal and the original UTC/QPC bounds must all be valid. Restoration cannot create a new duration, substitute a new connection identity or turn an expired record into a refresh. Source/output consent and the authenticated transport remain separate admission requirements.

The native experiment demonstrated a writer process exiting before another process reads its protected record in the same Windows logon. It did not exercise another real logon, OS restart, suspend, hibernation or physical playback. Those states remain separate gates; unsupported continuity must require a fresh verified grant.

## Mutation ordering to establish before enabling recovery

| Transition | Required ordering and failure result |
| --- | --- |
| Positive membership observation | Validate the captured account/login, request and device identities, commit the exact finite evidence, then publish recovery eligibility. A failed write cannot be reported as a saved grant. |
| Revocation-capable network operation | Establish a durable owned pending observation before sending the request. If preparation fails, do not send that operation. This candidate protocol still needs implementation and fault tests. |
| Known negative result | Revoke affected runtime consumers immediately. Atomically record the negative fact and retire only its owned pending observation. If completion cannot persist, the pending record must continue to deny restart recovery. |
| Temporary failure or cancellation | Settle the underlying operation before deciding whether its owned marker can be cleared. A canceled UI waiter cannot discard a completed negative response. No completed failure extends an existing grant. |
| Sign-out or account replacement | Commit an authoritative cleared/replaced record with a new revision. A late writer from the previous login must fail its revision/login check. A failed durable sign-out must remain visibly failed. |
| Corrupt, unknown or inaccessible record | Preserve the distinct failure. Do not fall back to an earlier credential file, an empty cache or a newly generated login identity. |

The pending-observation protocol addresses a specific gap: adding checkpoint serialization alone could allow restart to restore an old grant after a negative observation could not be saved. Compare-and-swap prevents stale owners from overwriting newer state; it does not by itself solve a failed invalidation write. This protocol is a candidate design, not a claim that the current application already provides the property.

`AudioAccountRegistryObserver` currently has `Begin`, `Listed`, `Removed` and `Rejected` callbacks. Durable integration must also settle every operation that exits with a transport failure or cancellation. This affects presence, list, registration, removal and credential-refresh call paths, not only the playback provider's direct GET. Completion must retain captured ownership and must not follow the currently displayed account to a replacement login.

Disk and network work must stay outside the playback effect gate. That gate remains a bounded in-memory check of the exact consumer, account epoch and finite evidence. Persistence needs its own bounded ownership protocol; acquiring it must not hold the carrier or output lock.

## Migration and native validation

Migration must preserve existing credentials while adding no audio authority to schema-1 data. Once a canonical cleared or newer record exists, it must take precedence over legacy content. The storage layout, older-client coexistence and crash boundaries must be decided and tested together before changing the product schema.

The current native file experiments prove process-stop boundaries before and after the commit call, rejection with complete records retained while a target is open, and file-lease release after its owner terminates. Both the old `File.Move` and the new write-through path reject an open replacement target in the measured Windows environment, even with `FileShare.Delete`. Readers must close before committing; there is no new delete-first or retry path. The [Windows rename contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information) distinguishes standard replacement from POSIX semantics.

Required acceptance still includes:

- Real two-process stale-write races, including an old asynchronous writer after sign-out and same-account relogin.
- Failure before request preparation, after a known negative, during replacement and during cleanup, with separate restart readback.
- Overlapping credential and registry observations, including canceled waiters and changed owners.
- Legacy migration, authoritative cleared-state precedence, corruption and unavailable protection.
- Recovery of the original deadlines without renewal, plus expiry, clock rollback and logon mismatch rejection.
- Product startup, authenticated USB/Wi-Fi reconnection and actual strict audio output using restored evidence.

Power-loss durability and interruption inside the rename syscall were not tested. [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw) documents the write-through request; successful process-interruption experiments are not a substitute for those stronger failure conditions. Detailed native receipts are tracked in [the output qualification record](windows-audio-native-output.md).
