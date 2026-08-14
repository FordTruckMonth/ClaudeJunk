---
name: annas-archive
description: Search and download books and academic papers from Anna's Archive. Use when the user wants to find, look up, or download a book, ebook, textbook, paper, or article.
version: 0.1.0
author: ClaudeJunk
license: MIT
platforms: [macos, linux]
metadata:
  hermes:
    tags: [Research, Books, Papers]
    related_skills: []
required_environment_variables:
  - name: ANNAS_SECRET_KEY
    prompt: "Anna's Archive donor API key (leave blank for search-only)"
    help: "Get one by donating at https://annas-archive.org/donate. Searching works without it; downloads require it."
    required_for: "Downloading books and papers"
  - name: ANNAS_DOWNLOAD_PATH
    prompt: "Absolute directory for downloaded files (optional)"
    help: "Must be an absolute path, e.g. /home/you/Downloads/annas. If unset, the skill defaults to ~/Downloads/annas."
    required_for: "Downloading books and papers"
---

# Anna's Archive

Search and download books and academic papers from [Anna's Archive](https://annas-archive.org)
using the [`annas-mcp`](https://github.com/iosifache/annas-mcp) CLI, wrapped here as
`scripts/annas`. Searching is free; **downloading requires a donor API key** in
`ANNAS_SECRET_KEY`.

## When to Use

- The user wants to **find** a book, ebook, textbook, or academic paper.
- The user wants to **download** a specific book (by title/author) or paper (by DOI).
- The user gives a DOI (`10.xxxx/...`) and wants the PDF.

Do **not** use for general web search or for content the user already has locally.

## Quick Reference

All commands go through the wrapper, which locates the binary and sets defaults:

```bash
annas="${HERMES_SKILL_DIR}/scripts/annas"

# One-time: install the annas-mcp binary into the skill (only if the wrapper says it's missing)
"${HERMES_SKILL_DIR}/scripts/setup.sh"

# Search books by title / author / topic  (no key needed)
"$annas" book-search "designing data-intensive applications"

# Download a book: hash comes from search; filename MUST include the extension
"$annas" book-download <md5-hash> "Designing Data-Intensive Applications.epub"

# Search papers by keywords, or look up a DOI directly (no key needed)
"$annas" article-search "attention is all you need"
"$annas" article-search "10.1145/3292500.3330701"

# Download a paper by DOI
"$annas" article-download "10.1145/3292500.3330701"

# Slow mirror? add a longer timeout to any command:
"$annas" --timeout 10m book-download <hash> "Big Book.pdf"
```

`book-search` prints one block per result:

```
Book 1:
Title: ...
Authors: ...
Publisher: ...
Language: ...
Format: epub
Size: ...
URL: ...
Hash: <md5>          <-- pass this to book-download
```

## Procedure

**Downloading a book:**
1. Run `book-search` with the user's title/author/topic.
2. Show the top few results and pick (or let the user pick) the best `Format`/`Language`.
3. Build a filename from the title **with the matching extension** (e.g. `.epub`, `.pdf`).
4. Run `book-download <Hash> "<Title>.<format>"`. The file lands in `ANNAS_DOWNLOAD_PATH`
   (default `~/Downloads/annas`); the command prints the full path.

**Downloading a paper:**
1. If the user gave a DOI, go straight to `article-download "<doi>"`.
2. Otherwise `article-search "<keywords>"`, confirm the right paper, then
   `article-download "<doi>"` using the DOI from the result.

**Search only:** just run the relevant `*-search` command and summarize results —
no API key required.

## Pitfalls

- **`ANNAS_SECRET_KEY and ANNAS_DOWNLOAD_PATH ... must be set`** — a *download* was
  attempted without the donor key or path. Searching still works; for downloads, set
  `ANNAS_SECRET_KEY` (Hermes prompts for it) and re-run.
- **`ANNAS_DOWNLOAD_PATH must be an absolute path`** — use a full path like
  `/home/you/Downloads/annas`, never `./x` or `~/x`. The wrapper defaults it to an
  absolute `~/Downloads/annas` when unset.
- **`filename must include an extension`** — `book-download` needs `Name.epub` /
  `Name.pdf`; the extension sets the format.
- **`annas-mcp: not found`** — run `scripts/setup.sh` once to install the binary.
- **Mirror unreachable / timeouts** — retry with `--timeout 10m`, or set
  `ANNAS_AUTO_BASE_URL=true` (auto-picks a live mirror) or `ANNAS_BASE_URL=<host>`.
- Only download content you have the right to access.

## Verification

- After a download, the command prints `... downloaded successfully to: <path>`.
  Confirm the file exists and is non-empty: `ls -lh "<path>"`.
- To confirm the skill is wired up without hitting the network:
  `"${HERMES_SKILL_DIR}/scripts/annas" --version` should print a version string.
