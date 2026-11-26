# Remyral release channel

This repository is the content of `https://releases.remyral.com`, the official release channel of
[Remyral](https://github.com/dotKa/remyral). It is published by Cloudflare Pages on every push.

| Path | What it is |
|---|---|
| `workers/feed.json`, `workers/feed.sig.json` | The signed worker release feed (`remyral-worker-feed/v1`) |
| `workers/<version>/release.json` | A signed worker release |
| `catalog/catalog.json`, `catalog/catalog.sig.json` | The signed version catalog of AI coding runtimes |
| `control-plane/feed.json`, `control-plane/feed.sig.json` | The signed control-plane release feed (`remyral-control-plane-feed/v1`) |
| `control-plane/<version>/` | A signed control-plane release: `manifest.json` + `manifest.sig.json`, `install.sh`, compose files, notes |

Every file here is signed with the Remyral release keys and is verified by the worker and the installer
before use, so a copy of this channel can be mirrored anywhere. To run your own channel with your own keys,
see `docs/ops/update-channel.md` in the main repository.

Only recent releases are kept; older ones remain available from earlier commits of this repository.
