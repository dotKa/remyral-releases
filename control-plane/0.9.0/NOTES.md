# Remyral 0.9.0

This is the first public release of the control plane (0.9.0, before 1.0); the entries below describe the changes relative to earlier private builds.

### Added

- The source code is published under the Apache License 2.0 (`LICENSE`, `NOTICE`, `TRADEMARKS.md`, and
  `THIRD_PARTY_NOTICES.md` for the licences of dependencies and container images).
- The code, tests and fixtures contain no values specific to one installation: host names, e-mail addresses, machine
  names and paths are configuration or example values. A fresh install has no preset support address; diagnostics
  reports are e-mailed only to an address the owner enters.
- The worker no longer bundles the proprietary Claude Agent SDK; it loads the SDK at run time from the Claude Code installation on the machine, and its bundles
  ship the licence texts of the third-party packages they contain.
- The deploy and publish scripts read the target host and the console domains from configuration instead of built-in
  defaults: `--host` or `REMYRAL_DEPLOY_HOST`, and `REMYRAL_DEPLOY_DOMAIN_PROD` / `REMYRAL_DEPLOY_DOMAIN_STAGING`.
- The web console serves the licence texts of its third-party packages and fonts at `/third-party-licenses.md`.
- The monitoring CloudFormation template has no default console domain; its `Domain` parameter is required.
- Leak check for the public repository: `pnpm check:leaks` (part of `pnpm verify`) refuses installation-specific
  content, and a CI `leaks` job runs it together with gitleaks on the tree and the full history
  ([docs/security/leak-check.md](docs/security/leak-check.md)).
- End-user guides in Turkish are published under `docs/guide/tr/` (index in `docs/guide/README.md`); generic host
  perimeter and access guidance is part of `docs/ops/deploy-coolify.md`.
- Contributor documentation: `CONTRIBUTING.md` (development setup, tests, Developer Certificate of Origin sign-off),
  `SECURITY.md` (private vulnerability reporting) and `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).

### Fixed

- The CI workflows get past Node setup again, and checkouts no longer keep the GitHub token in the git configuration.
- `pnpm scan:secrets` passes again: generated lockfiles and known test fixtures are recognised.

### Security

- Dependencies with published advisories were updated to their patched releases: fastify, and through the lockfile
  body-parser, qs, hono, @hono/node-server, fast-uri and (test-only) undici.
- Decrypting stored push-notification keys now states the expected authentication tag length explicitly.
- Tool archives that contain symbolic links can no longer place files outside their extraction directory.
- Requests to a self-managed GitLab and to an extension registry follow the same outbound address rules as other
  administrator-configured services, and credentials are never sent to another host after a redirect. A GitLab on a
  private network must be listed in the internal origins setting (`OPS_INTERNAL_ORIGINS`).
- Repository checks run by the control plane reach only public hosts, or hosts listed as internal origins.
- Bitbucket pull-request lookups refuse branch names that could change the search query.
- A captured GitHub webhook delivery replayed under a new delivery id no longer starts an automation again.
- One-time links and similar credential values in a request's query string are masked in the request logs.
- A stored Coolify token can only be decrypted for the connection it was saved for.
- IDE answers from a machine are accepted only from the machine the request was sent to.
- Pending machine pairings are limited per network, so requests from a few networks can no longer block pairing for
  everyone, and owners are notified once per network instead of once per request.
- The metrics endpoint refuses to start on a non-loopback address without a bearer token (`METRICS_TOKEN_FILE`).
- Vault credentials named directly in a job's or a service's secret references are now limited to the credentials
  the job's own project gives its jobs as environment variables (kind "Other", bound under Projects → Policy →
  Environment variables), at every way a job is created and again at assignment; other references are refused with
  the variable name. Workers additionally receive the allowed credentials in a signed part of the lease and inject no
  other vault credential (older workers and masters keep working; the check then applies on the master only). A
  saved automation, schedule or workflow step that names any other vault credential fails its next run with the
  variable name.
- A worker injects one of its own locally stored secrets into a job or service only when the machine's owner exposed
  that name to jobs (`remyral-worker secret expose <name> [--project <id>]`); by default none is. An existing install
  whose jobs named local secrets in their secret references runs those jobs without the variable until the owner
  exposes it; the job timeline names the variable.
- Secret references that were not injected (refused by the project's rules or not exposed on the machine) are shown
  in the job's timeline by variable name.
- Vault credential ids are shown only to those who may change the corresponding setting (project environment
  variables, MCP secret slots, repository credentials, runtime API-key accounts); others see names.
- A service started again from its stored definition checks its vault secrets again and is stopped when the project
  no longer gives one of them to its jobs.
- Conversation exports in Markdown no longer carry raw HTML or script links from message text into the file; code
  blocks are kept as they are.
- The worker's MCP server check connects to the address it validated instead of resolving the name again for each
  request (DNS rebinding).
- A worker accepts a rollback offer only to the previous version it still keeps locally, not to any older signed
  release; the minimum-version floor is unchanged.
- The worker's privileged helper accepts master-signed machine-administration sessions, commands and privileged
  requests only for the worker id recorded locally by root/Administrator (`admin-bind`, done by the installer on an
  enrolled machine); machine administration on a new machine needs that one step after its approval.
- The worker installers can set the machine's local ceiling for AI machine administration both ways
  (`--allow-machine-admin` / `--no-machine-admin`, Windows `-AllowMachineAdmin` / `-NoMachineAdmin`), also on an
  existing configuration; the machine-administration guide states what a compromised control plane could do and how to
  lock a machine down. The default is unchanged.
- A worker whose host jobs fall back to running without filesystem confinement now reports it as a warning with the
  cause and the fix, and refuses AI machine administration in that state unless the machine's owner opts in locally;
  the sandbox guide states what that mode exposes and how to get confinement on Ubuntu 24.04.
- A new installation starts on the Dengeli (Balanced) security preset instead of Serbest (Free), so an authenticator
  code is asked for machine administration, the sandbox, production deploys, credentials and integrations until the
  owner chooses otherwise. The default applies to new installations; a configured preset is never changed by an
  update. The setup wizard, Settings → Security and
  the guides state what each preset waives.
- The assistant no longer acts directly in a turn that has read content you did not write (a job log or output, a
  repository file or diff, a web response, an attachment, a machine's output), nor in later system-written turns of
  that conversation: such actions wait on the usual confirmation card. When you confirm one you can tick "Remember
  this" so the same kind of action on the same target runs without asking again; remembered confirmations are listed
  and can be forgotten in Settings → Chat. Machine administration, approval decisions, settings, credentials, memory,
  installs and deletions are always asked in such a turn. Listing pending merge decisions does not count as such
  content: the assistant sees only the fields the platform generated for them (branch, counts, check states), so
  "approve the PRs" runs at once again; a listing that includes a tool approval written by an agent still does.
