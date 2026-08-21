# Data Broker Opt-Out Automation (BADBOOL + Thunderbird)

Semi-automates working through the
[Big Ass Data Broker Opt-Out List](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List)
("BADBOOL", by Yael Grauer): you enter your details once, and the tool
generates personalized deletion/opt-out request emails, opens them as
**pre-filled Thunderbird compose windows**, walks you through the
web-form-only brokers in your browser, and tracks what you've sent, what's
confirmed, and which requests are overdue for a follow-up.

No dependencies — Python 3.11+ standard library only. Nothing about you
ever leaves your machine except the emails you choose to send.

## Why "semi"-automated?

Two realities of the opt-out world shape this tool:

1. **Most brokers only take web forms.** Many opt-outs require you to first
   find your own listing URL, solve a CAPTCHA, or click a confirmation link
   emailed to you. That part can't be honestly scripted — so the tool opens
   the right pages, shows you BADBOOL's exact instructions, and tracks your
   progress instead.
2. **Emails should be reviewed before sending.** For brokers that accept
   email opt-outs, the tool pre-fills everything (recipient, subject,
   legally-grounded request body with your details) and opens it in
   Thunderbird — you glance at it and press Send. A fully unattended SMTP
   mode exists too if you want it.

## Quick start

```console
$ cd data-broker-optout
$ python3 optout.py init          # answer a few questions -> me.toml
$ python3 optout.py compose       # Thunderbird windows for email opt-outs
$ python3 optout.py forms         # guided browser walkthrough for the rest
$ python3 optout.py status        # where you stand, what's overdue
```

Six weeks later:

```console
$ python3 optout.py followup      # compose follow-ups for ignored requests
```

## Commands

| Command | What it does |
| --- | --- |
| `init` | Interactive setup — writes `me.toml` with your name, addresses, phones, emails. |
| `list [--method email\|form] [--priority crucial\|high\|normal] [--status ...]` | All brokers, their method and your status. |
| `show <id>...` | Full BADBOOL instructions, URLs, and your history for a broker. |
| `compose [ids...] [--dry-run] [-y]` | Open a pre-filled Thunderbird compose window per email-based broker, in batches. Prompts (optionally) for your listing URL on each site. `--all-email` also includes brokers where email is only a fallback route. |
| `forms [ids...]` | For each form-based broker: opens the search + opt-out pages in your browser, prints the steps, then records the outcome (`done` / `sent` / `blocked` / `n/a` / postpone). Resumable. |
| `eml [ids...]` | Writes RFC-822 `.eml` drafts to `outbox/` instead (open in Thunderbird, press Ctrl+E "Edit As New Message", send). |
| `mailto` | Writes `mailto.html` — one pre-filled `mailto:` link per broker, for any default mail client. Links carry a condensed request (OSes truncate long `mailto:` URLs); `compose`/`eml` produce the full letter. |
| `send [ids...] [-y]` | Fully unattended: sends via SMTP directly (settings copied from Thunderbird's Outgoing Server config; password via `OPTOUT_SMTP_PASSWORD` env var or prompt). No review window — use deliberately. |
| `mark <id>... <status> [--note ...]` | Manually set status (`pending`, `in-progress`, `sent`, `followup-sent`, `done`, `blocked`, `na`). |
| `status` | Dashboard: progress counts, requests awaiting confirmation, overdue ones, suggested next action. |
| `followup [--dry-run]` | Compose follow-up emails for requests past the deadline (default 45 days, per CCPA). |
| `check-upstream` | Fetches the live BADBOOL README and reports brokers added/removed since `brokers.json` was generated. |

## How the Thunderbird integration works

`compose` shells out to Thunderbird's command line interface:

```console
$ thunderbird -compose "to='privacy@broker.com',subject='...',message='/path/to/body.txt'"
```

The `message=` field points at a text file (written to `outbox/`) that
becomes the email body — this sidesteps all the quoting problems of putting
multi-line bodies on the command line. If Thunderbird is already running,
the windows open in your existing session. Flatpak/Snap/Windows users: set
`[thunderbird] binary` in `me.toml` (see `me.example.toml`).

Windows are opened in batches (default 5, configurable) so you can review
and send at your own pace.

## The data

`brokers.json` is a structured export of BADBOOL: for each broker its
priority (💐 crucial / ☠ high / normal), opt-out URLs, opt-out email
addresses, phone numbers, flags (📞 phone required, 🎫 ID requested,
💰 paid), which sister sites the opt-out also covers, and a condensed
version of BADBOOL's step-by-step instructions. Only brokers that publish
an opt-out **email address** get the email treatment; everything else is
handled by `forms`.

BADBOOL changes regularly — run `check-upstream` now and then, and consult
the original list for anything marked stale.

### Suspect entries

Three entries in the fetched copy of the list point at sites that are not
data brokers (a bioinformatics project, a nonprofit's staff directory, a
UNESCO campaign site). They are kept in `brokers.json` for transparency but
carry a `suspect` flag with an explanation: the tool excludes them from all
default runs, marks them `!` in `list`, and asks for explicit confirmation
before opening their pages. One of them ("Clustal") is a corrupted variant
of ClustrMaps' well-known opt-out procedure, so a proper `clustrmaps` entry
has been restored alongside it. See `show clustal men-stopping-violence
unite-4heritage` for details, and verify against the upstream list.

## Ground rules (inherited from BADBOOL)

- **Never give a broker information it doesn't already have.** Search for
  your listing first; only include in requests the details already shown
  publicly. The templates only include fields you put in `me.toml`, and
  `init` reminds you of this.
- Cross out your ID number if a broker (e.g. PimEyes) demands a license.
- Some brokers need one opt-out per listing, or per email address — see the
  per-broker `notes` in `show <id>`.
- California residents: the state's [DROP portal](http://consumer.drop.privacy.ca.gov)
  can send deletion requests to 500+ registered brokers at once — do that
  first, then use this tool for the rest.

## Privacy of this tool itself

`me.toml` (your details), `state.json` (your progress), `outbox/` (email
bodies), and `mailto.html` are all listed in `.gitignore` — they stay on
your machine. Review what you commit if you fork this repo.

## Attribution & license

Broker data condensed from the
[Big Ass Data Broker Opt-Out List](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List)
© Yael Grauer, licensed [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
`brokers.json` is an adaptation of that list and is therefore likewise
CC BY-NC-SA 4.0. Support the original project — it's the one doing the
hard research. The code in this directory is provided under the same terms.
