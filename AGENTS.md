# WordShield Corp development boundaries

This is the independent `Syrmus/wordshield-corp` repository, default branch `main`. Read `CORP.md` before corporate implementation work.

- Keep all corporate changes in this checkout and branch. Do not switch, edit, reset, commit, or deploy the user's personal checkout as part of Corp work.
- Never run the inherited macOS deployment/update scripts against the personal Mac mini for Corp work. They are historical personal-edition tooling, not corporate deployment tools.
- Use separate synthetic-only test data, storage directories, secrets, service names and ports. Do not read or copy personal production documents, session databases, credentials or encryption keys.
- No production rollout, public exposure, or changes to corporate identity/network infrastructure without explicit authorization and a verified target.
- Use `deploy/corp` and `docs/corp` for the Linux pilot. Historical macOS instructions are personal-edition only. Real GPU and corporate identity acceptance are still required before production rollout.
- Preserve existing local-only processing and account isolation. Do not bypass fail-closed safety checks to make Linux startup succeed.
- Never merge into or push to `Syrmus/wordshield-local` as part of Corp work. Release publication requires explicit direction. The historical `corp` branch in that repository is a rollback reference, not the active corporate source.
