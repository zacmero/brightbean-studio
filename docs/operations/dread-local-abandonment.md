# Dread local abandonment, October23

Operator explicitly abandoned the Dread VM scope and waived a new archive copy.
This exception never applies to PA, RP or Holy and never changes Drive.

`apps.media_library.storage_archive.abandon_dread_local_asset(id, authorization, execute=False)`
provides a read-only dry run; execute=True requires the same frozen generation
identities, exact13IDs, archived workspace, disconnected account with blank local
OAuth tokens, terminal published bindings, no global consumers/jobs/multipart
uploads, fresh host inode proof, native conditional S3 support and exact key seals.
No service or generic deletion endpoint invokes this mode automatically.

Authorization and receipts live privately under the existing storage state scopes
directory. The operation identity is `dread-local-abandonment-20261023`. Dry-run
SHA256/size/ETag must be frozen into authorization.assets[id].objects before
execution. Persist UNKNOWN before each If-Match DELETE; reconcile an absent
object only from matching durable identity. Unexpected generations fail closed.

MediaAsset, PostMedia and publication rows remain. `_local_abandonment` records
per-key identities/outcomes. A legacy `_archive` protection marker is explicitly
NOT_ARCHIVED / restore_available=false; it protects rows in already-running
workers and must never be interpreted as Drive verification or a restore promise.
The updated native delete/orphan helpers also preserve abandonment tombstones.

No Drive API calls, remote OAuth revocation, new archive namespaces or generic
retention policy changes occur. Native MinIO GC must release the measured payload
inodes before physical space is reported. Keep original deployment baselines and
protected schedules intact; deployment requires no unrelated worker restart.
