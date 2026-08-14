# annas-mcp + Hermes Agent

Search and download books and academic papers from
[Anna's Archive](https://annas-archive.org) inside
[Nous Research's Hermes Agent](https://github.com/NousResearch/hermes-agent),
powered by [`annas-mcp`](https://github.com/iosifache/annas-mcp).

There are two ways to wire this up — pick one:

- **Option A — Hermes skill (recommended).** A self-contained skill in
  [`skills/annas-archive/`](./skills/annas-archive/) that drives the `annas-mcp`
  **CLI**. Drop it in `~/.hermes/skills/`, and it activates automatically and as
  the `/annas-archive` slash command. No `config.yaml` edits. Your donor key is
  sourced from the environment via the skill's `required_environment_variables`
  (Hermes prompts for it) — nothing secret is stored in the repo.
- **Option B — MCP server.** Register `annas-mcp mcp` as a stdio MCP server in
  `~/.hermes/config.yaml` so `book_search` / `book_download` / etc. appear as
  first-class tools. See [MCP server setup](#option-b--mcp-server-setup) below.

---

## Option A — Hermes skill (recommended)

**Install:** copy the skill into your Hermes skills dir and install the binary once.

```bash
# from this directory
cp -r skills/annas-archive ~/.hermes/skills/annas-archive
~/.hermes/skills/annas-archive/scripts/setup.sh   # builds via `go install` or downloads a release
```

Then in a Hermes session run `/reload-mcp` (or restart), and use it:

```
/annas-archive find and download the epub of "designing data-intensive applications"
```

or just ask naturally — the skill activates on book/paper requests.

**Providing your key (you manage it, not the repo):** the skill declares
`ANNAS_SECRET_KEY` (and optional `ANNAS_DOWNLOAD_PATH`) as
`required_environment_variables`, so Hermes sources them from your environment /
prompts for them. Set the key wherever you keep secrets, e.g.:

```bash
export ANNAS_SECRET_KEY=your-donor-key          # only needed for downloads
export ANNAS_DOWNLOAD_PATH=/absolute/path        # optional; defaults to ~/Downloads/annas
```

Searching needs no key. Downloads require a donor key
(<https://annas-archive.org/donate>). Full details:
[`skills/annas-archive/SKILL.md`](./skills/annas-archive/SKILL.md).

The skill uses these CLI commands under the hood:

| Command | What it does |
|---|---|
| `annas book-search "query"` | Search by title, author, or topic (prints metadata + MD5 hash). |
| `annas book-download <hash> "Title.epub"` | Download a book (needs a donor key). Filename extension sets the format. |
| `annas article-search "keywords \| DOI"` | Search papers, or look up a DOI (`10.…`) directly. |
| `annas article-download "<doi>"` | Download a paper by DOI (needs a donor key). |

---

## Option B — MCP server setup

Hermes loads MCP servers from `~/.hermes/config.yaml`. `annas-mcp` speaks MCP
over stdio via its `mcp` subcommand, so Hermes launches it as a local stdio
server.

### Tools it exposes

| Tool | What it does |
|---|---|
| `book_search` | Search Anna's Archive by title, author, or topic. Returns metadata incl. the MD5 hash. |
| `book_download` | Download a book by its MD5 hash (needs a donor key). |
| `article_search` | Search academic articles/papers by DOI or keywords. |
| `article_download` | Download a paper by DOI (needs a donor key). |

Search works without an API key. **Downloads require an Anna's Archive donor
key** (`ANNAS_SECRET_KEY`), obtained by donating: <https://annas-archive.org/donate>.

### Quick start (scripted)

```bash
cd hermes-annas-mcp
cp .env.example .env         # then edit .env with your key + download path
./install.sh
```

`install.sh` will:

1. Install the `annas-mcp` binary to `~/.local/bin` — via `go install` if Go is
   present, otherwise by downloading the matching release archive.
2. Create your download directory.
3. Merge an `annas-archive` entry into `~/.hermes/config.yaml` (existing servers
   are preserved; re-running updates the entry in place).

Then, in a Hermes session, run `/reload-mcp` (or restart Hermes) and the four
tools appear in the registry.

### Manual setup

If you'd rather not run the script:

**1. Install the binary** (pick one):

```bash
# With Go:
GOBIN="$HOME/.local/bin" go install github.com/iosifache/annas-mcp/cmd/annas-mcp@latest

# Or download a prebuilt binary from:
#   https://github.com/iosifache/annas-mcp/releases
# and put it somewhere on your PATH, e.g. ~/.local/bin/annas-mcp
```

**2. Add the server to `~/.hermes/config.yaml`** — merge the block from
[`config.snippet.yaml`](./config.snippet.yaml) under your `mcp_servers:` key,
replacing the placeholder values:

```yaml
mcp_servers:
  annas-archive:
    command: "annas-mcp"        # absolute path if not on Hermes' PATH
    args: ["mcp"]
    env:
      ANNAS_SECRET_KEY: "your-donor-key"
      ANNAS_DOWNLOAD_PATH: "/absolute/path/to/downloads"
      ANNAS_BASE_URL: "annas-archive.gl"
```

**3. Reload:** `/reload-mcp` in a session, or restart Hermes.

### Calling it from Hermes

Once loaded, just ask Hermes naturally ("search Anna's Archive for _Designing
Data-Intensive Applications_ and download the epub"), or invoke the tools
directly:

```
book_search      query="designing data-intensive applications"
book_download    hash=<md5 from the search results>
article_search   query=10.1145/3292500.3330701
article_download doi=10.1145/3292500.3330701
```

## Configuration reference

| Env var | Required | Default | Notes |
|---|---|---|---|
| `ANNAS_SECRET_KEY` | for downloads | — | Donor API key. Searching works without it. |
| `ANNAS_DOWNLOAD_PATH` | yes | — | **Must be absolute.** Where files are written. |
| `ANNAS_BASE_URL` | no | `annas-archive.gl` | Mirror hostname. |
| `ANNAS_AUTO_BASE_URL` | no | `false` | `true` = auto-discover a live mirror via [SLUM](https://open-slum.org/). |

Hermes launches stdio servers with **only** the env vars declared in the
`env:` block (it does not forward your whole shell environment), so these must
be set there, not just in your shell.

### Verifying without Hermes

You can smoke-test the binary's MCP interface directly over stdio:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
| ANNAS_SECRET_KEY=x ANNAS_DOWNLOAD_PATH="$PWD" annas-mcp mcp
```

You should get an `initialize` result naming `annas-mcp`, followed by a
`tools/list` result containing the four tools above.

## Troubleshooting

- **Tools don't show up:** run `/reload-mcp`, or restart Hermes. Confirm the
  `command` path is correct and executable (`annas-mcp --version`).
- **"ANNAS_DOWNLOAD_PATH must be an absolute path":** use a full path like
  `/home/you/Downloads/annas`, not `./downloads` or `~/downloads`.
- **Downloads fail / 401:** you need a valid donor `ANNAS_SECRET_KEY`. Search
  still works without one.
- **Mirror unreachable:** set `ANNAS_AUTO_BASE_URL: "true"` to let it pick a
  live mirror, or change `ANNAS_BASE_URL`.
