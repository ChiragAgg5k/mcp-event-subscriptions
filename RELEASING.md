# Publishing to PyPI

The first release is `0.1.0a1`, an alpha. The package and specification remain
experimental. Publishing a version is permanent: PyPI does not allow replacing
its uploaded distribution files. Use a new version for subsequent fixes.

## One-time account setup

Sign in to PyPI, then open [account publishing](https://pypi.org/manage/account/publishing/).
Under **Add a new pending publisher**, select GitHub and enter:

| Field | Value |
| --- | --- |
| PyPI project name | `mcp-event-subscriptions` |
| Repository owner | `ChiragAgg5k` |
| Repository name | `mcp-event-subscriptions` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

Click **Add**. This authorizes only the configured GitHub workflow/environment.
No API token or GitHub secret is required. A pending publisher creates the PyPI
project on its first successful upload; it does not reserve the name beforehand.
The repository has a `pypi` GitHub environment matching the workflow.

References: [PyPI pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
and [publishing with a trusted publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/).

## Release

1. Update `project.version` in `pyproject.toml` for later releases, run `uv lock`,
   and commit the result. For this first alpha the version is already correct.
2. Wait for CI to pass for the intended release commit.
3. Create a GitHub release with a tag matching the version, e.g. `v0.1.0a1`,
   targeting that commit. Mark alpha releases as prereleases.
4. Publish the GitHub release. `.github/workflows/publish.yml` validates the
   tag/version match, runs checks, builds distributions, checks metadata and
   tests the installed wheel before publishing through GitHub OIDC.
5. Verify the project/version on PyPI and install from PyPI in a clean environment.

The publishing job downloads only the built artifacts; it does not check out or
execute repository code. OIDC permissions are limited to that job. Actions are
pinned to commit hashes. Default PyPA upload attestations are enabled.

## Retry a failed publishing run

If the initial upload fails because the pending publisher was not configured,
add it on PyPI, then rerun the failed job. Alternatively manually dispatch
**Publish to PyPI** with the existing version tag. Do not rerun an already
successful upload; published files cannot be overwritten.
