<!--
Thanks for opening a PR. A few things make review go faster:

  - Commit messages follow Conventional Commits (see DEVELOPMENT.md).
  - `make check` passes locally before pushing -- the pre-push hook
    runs it automatically if you ran `make setup`.
  - New checks include unit tests covering both pass and fail cases.

Delete the sections below that don't apply.
-->

## Summary

<!--
One paragraph: what changes, and why. Link the issue this resolves
("Closes #N") or the ADR this implements ("Refs ADR-N").
-->

## Type

- [ ] feat — new feature
- [ ] fix — bug fix
- [ ] docs — documentation only
- [ ] refactor — code change with no feature / fix
- [ ] test — adding or fixing tests
- [ ] build / ci / chore — tooling

## Verification

<!-- How did you check this works? `make check` is the minimum. -->

- [ ] `make check` passes locally
- [ ] New checks include unit tests with both pass and fail cases
- [ ] If touching the resource graph or core types, ARCHITECTURE.md is updated
- [ ] Commit messages follow Conventional Commits (DEVELOPMENT.md)

## Breaking changes

<!--
If this changes a public API, CLI flag, config schema, or check ID,
describe the migration path. Use `feat!:` or `fix!:` in the commit
subject AND include a `BREAKING CHANGE:` footer with details.
-->

None.

## References

<!--
- Closes #N
- Refs ADR-N
- Related to #M
-->
