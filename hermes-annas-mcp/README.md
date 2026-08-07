# annas-mcp + Hermes Agent

Wire the [Anna's Archive MCP server](https://github.com/iosifache/annas-mcp)
(`annas-mcp`) into [Nous Research's Hermes Agent](https://github.com/NousResearch/hermes-agent)
so you can search and download books and papers from inside a Hermes session.

Hermes loads MCP servers from `~/.hermes/config.yaml`. `annas-mcp` is a single
Go binary that speaks MCP over stdio via its `mcp` subcommand, so Hermes just
launches it as a local stdio server.

## Tools it exposes

| Tool | What it does |
|---|---|
| `book_search` | Search Anna's Archive by title, author, or topic. Returns metadata incl. the MD5 hash. |
| `book_download` | Download a book by its MD5 hash (needs a donor key). |
| `article_search` | Search academic articles/papers by DOI or keywords. |
| `article_download` | Download a paper by DOI (needs a donor key). |

Search works without an API key. **Downloads require an Anna's Archive donor
key** (`ANNAS_SECRET_KEY`), obtained by donating: <https://annas-archive.org/donate>.

## Quick start (scripted)

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

## Manual setup

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

## Calling it from Hermes

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

## Verifying without Hermes

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
