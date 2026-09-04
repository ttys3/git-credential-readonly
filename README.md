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

The helper supports Git's credential actions and an explicit management UI:

```text
git-credential-readonly <get|store|erase|manage|tui>
```

Git can call `get` as usual. The `store` and `erase` actions remain no-ops so
Git can never mutate credentials implicitly; only an interactive user in the
management UI can add, edit, or delete an entry.

For a single default credential file, configure it as follows:

```shell
git config --global credential.helper readonly
```

## Manage credentials with the TUI

Run the interactive manager with:

```shell
git-credential-readonly manage
```

The TUI is built with the actively maintained
[Bubble Tea](https://github.com/charmbracelet/bubbletea) framework and its
official [Bubbles](https://github.com/charmbracelet/bubbles) components. Use
the arrow keys or `j`/`k` to select an entry, <kbd>Enter</kbd> to edit it, and
`/` to filter a long list. `tui` is an alias for `manage`.

The manager provides two storage backends:

| Backend | Secret storage | Notes |
| --- | --- | --- |
| System keyring (recommended) | macOS Keychain, Linux/BSD Secret Service, or Windows Credential Manager | The password or token never appears in the on-disk index. |
| Credential file | The selected `--file` in standard `git-credential-store` URL format | Preserved for complete compatibility with existing installations. |

New credentials are entered as separate protocol, host, path, username, and
password/token fields. The manager validates every field and performs the URL
encoding, so characters such as `@`, `:`, `/`, `+`, `?`, and `#` in a token do
not corrupt the credential URL. Passwords and tokens are masked, omitted from
the list and confirmation screens, and never written to the debug log. When
editing an entry, leave the password/token field empty to retain its current
value.

Deleting an entry requires a separate confirmation. Credential-file updates
preserve unrecognized lines, reject concurrent changes, place specific paths
before broader scopes, and replace the file atomically with mode `0600` on
POSIX systems. Writes use Git's temporary `<file>.lock` convention and remove
the lock by atomically renaming it into place, following Git's
[official lockfile protocol](https://github.com/git/git/blob/v2.55.0/lockfile.h),
so the file remains interoperable with `git credential-store`.

### Use the system keyring for Git lookups

The default lookup backend remains `file`, so upgrading does not change any
existing Git configuration. After adding credentials to the system keyring,
opt in with `--backend keyring`, or use `auto` to check the keyring first and
then fall back to the configured credential file:

```ini
[credential]
	helper =
	helper = readonly --backend auto
	useHttpPath = true
```

Use a URL-specific credential section instead if only selected hosts should
send paths to helpers. See
[`credential.useHttpPath`](https://git-scm.com/docs/gitcredentials#Documentation/gitcredentials.txt-credentialuseHttpPath)
and the ordering guidance below. For safety, the keyring backend never returns
a path-scoped secret when Git omits the request path; enable `useHttpPath`, or
add an intentionally host-wide entry with an empty path.

The keyring backend uses
[`zalando/go-keyring`](https://github.com/zalando/go-keyring). On Linux and BSD,
a [Secret Service](https://specifications.freedesktop.org/secret-service-spec/latest/)
provider such as GNOME Keyring and a working D-Bus session must be available.
This is normally already true in a desktop login session; headless sessions
may need explicit setup. The `auto` backend can still fall back to the file if
the keyring cannot be reached.

Because the native keyring API cannot enumerate application secrets, the
manager keeps a versioned metadata index in the operating system's user config
directory, normally:

```text
~/.config/git-credential-readonly/keyring-index.json
```

The index contains only opaque IDs plus protocol, host, path, and username; it
never contains passwords or tokens and is written with mode `0600` on POSIX.
Each protected keyring payload also contains its own scope metadata, which is
verified against the index again before a credential is returned. Use
`--keyring-index <path>` only when a non-default metadata location is needed.
Keyring mutations are serialized with an empty `.transaction-lock` sidecar;
that advisory lock contains no credential data.
Edits create a new opaque keyring item before atomically switching the index;
old items remain in a metadata-only pending-cleanup list until they are deleted
from the keyring. A normal edit therefore never removes the old item before the
replacement is indexed, and interrupted cleanup is retried by the next keyring
change.

The TUI never migrates or deletes plaintext credentials automatically. Add and
verify the secure entry first, then explicitly delete the old file entry if
you want to complete a migration.

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

The TUI writes this exact format when the Credential file backend is selected,
so files remain usable by Git's built-in `credential-store` helper.

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
- [Git's atomic lockfile protocol](https://github.com/git/git/blob/v2.55.0/lockfile.h)
- [`credential.helper` configuration](https://git-scm.com/docs/gitcredentials#Documentation/gitcredentials.txt-credentialhelper)
- [`credential.useHttpPath` configuration](https://git-scm.com/docs/gitcredentials#Documentation/gitcredentials.txt-credentialuseHttpPath)
- [Git credential-context matching](https://git-scm.com/docs/gitcredentials#Documentation/gitcredentials.txt-CREDENTIALCONTEXTS)
- [Git's exact credential field matcher](https://github.com/git/git/blob/v2.55.0/credential.c#L81-L92)
- [Git's `credential-store` lookup loop](https://github.com/git/git/blob/v2.55.0/builtin/credential-store.c#L13-L47)
- [Git's credential URL parser](https://github.com/git/git/blob/v2.55.0/credential.c#L585-L653)
- [Git's credential URL decoder](https://github.com/git/git/blob/v2.55.0/url.c#L44-L102)
