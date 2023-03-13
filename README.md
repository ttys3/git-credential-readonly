# git-credential-readonly

this is a git credential helper that only reads from the credential store, and never writes to it.

in a word, it is a drop-in replacement for `git-credential-store` that only handle `get` action, and silently ignore `store` and `erase`.

it exists because the git built-in credential helper `store` will always write back to the credential store file.

which will cause problem when you have different store config for both user personal token and organization personal token.

for example:

```ini
[credential "https://github.com/org-name/"]
	helper = readonly --file ~/.git-credentials-org

[credential]
	helper = readonly
```

if you use `store` instead of `readonly`, it will always write back to the credential store file, 
which will cause problem after you use organization token, 
it will write the organization token back to the user credential store file.
so you personal token (by default in `~/.git-credentials`) will be overwritten by the organization token.
due to both auth host name are the same.

## install

```shell
go install github.com/ttys3/git-credential-readonly@latest
```

```shell
usage: `git-credential-readonly <get|store|erase>`

```shell
git config --global credential.helper readonly
```
## docs

https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage
