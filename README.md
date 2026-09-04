# git-credential-readonly

`git-credential-readonly` is a read-only replacement for
`git-credential-store`. It handles the `get` action and intentionally ignores
`store` and `erase`, so Git can retrieve credentials without modifying the
credential files.

This is useful when personal and organization tokens for the same host live in
different files. Git sends approved credentials to every configured helper;
using `store` for both files can therefore copy an organization token into the
personal credential file.

For example:

```ini
[credential "https://github.com/org-name/"]
	helper = readonly --file ~/.git-credentials-work

[credential]
	helper = readonly
```

With `readonly`, the organization token can be read from its dedicated file
without being written to the personal store at `~/.git-credentials`.

## Installation

```shell
go install github.com/ttys3/git-credential-readonly@latest
```

The helper supports these actions:

```text
git-credential-readonly <get|store|erase>
```

For a single default credential file, configure it as follows:

```shell
git config --global credential.helper readonly
```

## Multiple credentials and inherited helpers

The order of `credential.helper` entries is significant. Git tries helpers in
order until it has both a username and a password. An empty helper value has a
special meaning: it clears every helper collected before it.

This commonly affects users whose system Git configuration already selects a
helper such as:

- `osxkeychain` on macOS;
- `manager` or `manager-core` from Git Credential Manager;
- `libsecret` on Linux.

The following ordering is incorrect:

```ini
[credential "https://github.com/"]
	helper = readonly --file ~/.git-credentials-work

[credential]
	helper =
	helper = readonly
```

The empty value clears both the inherited system helper and the GitHub-specific
helper. Git then runs only `git credential-readonly get`, which reads the
default `~/.git-credentials` file and may fall back to prompting for a username.

The required order is:

1. reset inherited helpers;
2. add host- or organization-specific helpers;
3. add the general fallback helper last.

See the complete, sanitized [`examples/gitconfig`](examples/gitconfig) file:

```ini
[credential]
	helper =

[credential "https://github.com/"]
	helper = readonly --file ~/.git-credentials-work
	useHttpPath = true

[credential "https://git.example.com/"]
	helper = readonly --file ~/.git-credentials-work

[credential "https://gitlab.example.com/"]
	helper = readonly --file ~/.git-credentials-work
	useHttpPath = true

[credential]
	helper = readonly
```

Copy the relevant sections into `~/.gitconfig` and replace the example host and
file names as needed.

### Credential file examples

Git removes the HTTP(S) path before invoking external helpers unless
[`credential.useHttpPath`](https://git-scm.com/docs/gitcredentials#Documentation/gitcredentials.txt-credentialuseHttpPath)
is enabled. Git's built-in `credential-store` then compares a supplied path
exactly. This helper intentionally extends that behavior with slash-delimited
path scopes: `group/subgroup` matches both itself and descendants such as
`group/subgroup/project.git`, but it does not match `group/subgroup-backup`.
A trailing slash on a credential path is optional. Non-exact scope matches are
rejected when either path contains a `.` or `..` segment, including a
percent-encoded form that remains after Git's URL decoding.

Credential lines are checked from top to bottom, like `credential-store`, and
the first match wins. Put full repository paths before subgroup paths, and put
subgroup paths before broader organization or account paths.

`~/.git-credentials-work`:

```text
https://example-user:repository-token@github.com/example-org/private-repository.git
https://example-user:organization-token@github.com/example-org
https://example-user:subgroup-token@gitlab.example.com/group/subgroup
https://example-user:work-token@git.example.com
```

The default personal file may contain:

`~/.git-credentials`:

```text
https://example-user:personal-token@github.com/example-user
```

Credential files use the official
[`git-credential-store` storage format](https://git-scm.com/docs/git-credential-store#_storage_format):
one credential URL per line, without comments or blank lines. They contain
plaintext secrets. Never commit them, percent-encode special characters in
usernames and tokens, and restrict their permissions:

```shell
chmod 600 ~/.git-credentials ~/.git-credentials-work
```

### Troubleshooting

To see which helper Git actually executes without allowing an interactive
prompt, run:

```shell
GIT_TRACE=1 GIT_TERMINAL_PROMPT=0 \
git ls-remote --symref origin HEAD
```

For the example configuration, the trace should include:

```text
git credential-readonly --file ~/.git-credentials-work get
```

If it includes only the following command, check the ordering of the empty
helper and the URL pattern used by the scoped helper:

```text
git credential-readonly get
```

You can inspect where generic and GitHub-specific settings came from with:

```shell
git config --show-origin --show-scope --get-all credential.helper
git config --show-origin --show-scope \
  --get-all credential.https://github.com/.helper
```

## Documentation

- [Git credential storage](https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage#_a_custom_credential_cache)
- [`git credential` input/output format](https://git-scm.com/docs/git-credential#_inputoutput_format)
- [`git-credential-store` storage and lookup behavior](https://git-scm.com/docs/git-credential-store#_storage_format)
- [`credential.helper` configuration](https://git-scm.com/docs/gitcredentials#Documentation/gitcredentials.txt-credentialhelper)
- [`credential.useHttpPath` configuration](https://git-scm.com/docs/gitcredentials#Documentation/gitcredentials.txt-credentialuseHttpPath)
- [Git credential-context matching](https://git-scm.com/docs/gitcredentials#Documentation/gitcredentials.txt-CREDENTIALCONTEXTS)
- [Git's exact credential field matcher](https://github.com/git/git/blob/v2.55.0/credential.c#L81-L92)
- [Git's `credential-store` lookup loop](https://github.com/git/git/blob/v2.55.0/builtin/credential-store.c#L13-L47)
- [Git's credential URL parser](https://github.com/git/git/blob/v2.55.0/credential.c#L585-L653)
- [Git's credential URL decoder](https://github.com/git/git/blob/v2.55.0/url.c#L44-L102)
