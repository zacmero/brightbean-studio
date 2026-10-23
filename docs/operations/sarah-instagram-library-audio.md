# Sarah Instagram library audio

The Facebook-login Instagram provider accepts `PublishContent.extra.audio_configuration` for Reel/video posts. The publisher already merges each PlatformPost platform_extra into this object. No API/schema change or new publishing operation is introduced.

Required audio_id is an ASCII decimal string. audio_volume and video_volume are integers 1..100, default 100. Unknown fields, malformed IDs, and configuration on image/story/carousel posts fail permanently before provider requests. The existing JSON request transport serializes the object as nested JSON, not a Python repr or double-encoded string. Existing cover_url behavior remains intact.

Official schema: https://developers.facebook.com/documentation/instagram-platform/content-publishing/audio-api (live receipt October 23, 2026). The Sarah lane retains exact account, media, approval, operation identity, library metadata receipts and schedule readbacks. It alone binds the approved rows. Never retry publication because a music preview is unavailable. Reconcile the actual provider outcome after publication.

## Deployment October 23

A worker-only derivative of exact baseline c840956ce8697c49e6aa829e7a21c929ea0bd8adff6129ca1f2e5b8b08a37c2b changes only providers/instagram.py. Runtime image brightbean-shared:sarah-audio-worker-20261023, provider SHA256 05d71edd2b528349fd3cdfca176264d038fafc27bb36563b600967bfa7cbcd03. Preserve preexisting cover edits in the deployment snapshot. The app, inbox environment, storage overlays and old images remain unchanged.

Production compose order is compose.yaml, compose.sarah-inbox.yaml, compose.scoped-archive.yaml, compose.sarah-audio.yaml. The final overlay sets only services.worker.image to the new tag. Do not omit this overlay in later worker recreation. Portable build definition: Dockerfile.sarah-audio; freeze reviewed provider bytes in a minimal build context rather than copying unrelated dirty code.

Before deployment obtain current lane clearances and check global due posts, locked tasks, reservations, live publisher threads/open media. Native background_task SignalManager on Linux uses SIGTSTP to stop new intake after the current task returns; SIGTERM is not its graceful drain signal. Temporarily suppress automatic restart, request native drain, wait for exit0 and zero locked tasks, then recreate only worker with no dependencies. Do not force timeout/kill an active effect. Restore configured restart policy on the new worker.

Boundary October23 16:44:21 UTC: zero locked tasks, due posts within15min, active publication rows and idempotency reservations; worker one thread/no media FDs. Native drain exit0, worker recreated with unless-stopped policy, PID1345354. Six isolated focused tests passed both candidate and deployed imported provider, including real httpx JSON request encoding. No provider publish calls were made by tests.

Rollback uses the preserved scoped-archive-worker-20261013 image, with the same intake/effect safety checks. The new app process has not been deployed; scheduled publication uses the updated worker. Do not claim all long-lived app paths have the new provider.
