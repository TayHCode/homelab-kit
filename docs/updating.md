# Updating

Run collection manually, review `git diff`, update TODOs with your own agent or by
hand, then run `check`. Review before committing and pushing to your private repo.
The kit plugs into existing SSH configuration and backup practices; it does not
install services, create timers, contact models or schedule automatic updates.

v2 removes structured facts, manual device forms, fingerprints and approvals,
readiness and dependency ordering. Keep an existing v0.1 repo intact. Start a new
v2 documentation directory and copy reviewed prose and secret locations manually;
old inventories and observations are not automatically migrated.
