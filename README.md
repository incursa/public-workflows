# Incursa public workflows

Reusable, auditable release automation for Incursa public repositories.

## Dual NuGet publication

The [`publish-nuget-dual`](.github/actions/publish-nuget-dual/action.yml)
composite action promotes the exact package files produced by a caller to the
Incursa public feed and then to NuGet.org. The caller retains authority for its
protected GitHub environment, reviewers, package allowlist, and credentials.

The action:

- refuses to run for a non-public source repository;
- requires an exact allowlist of package IDs;
- records package IDs, versions, SHA-256 hashes, repository, and commit in a
  publication manifest;
- publishes to the Incursa public feed first and verifies an anonymous
  byte-for-byte read-back;
- publishes the same local files to NuGet.org and verifies all package entries
  except NuGet.org's repository signature; and
- safely resumes a partial release only when the already-published content
  matches.

Callers should pin this action to a full commit SHA.

```yaml
- uses: incursa/public-workflows/.github/actions/publish-nuget-dual@FULL_COMMIT_SHA
  with:
    packages-directory: out
    expected-package-ids: |
      Incursa.Example
      Incursa.Example.AspNetCore
    github-token: ${{ github.token }}
    incursa-api-key: ${{ secrets.NUGET_INCURSA_PUBLIC_PUBLISH_TOKEN }}
    nuget-api-key: ${{ secrets.NUGET_API_KEY }}
```
