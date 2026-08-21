#!/usr/bin/env python3
"""Data broker opt-out automation for the Big Ass Data Broker Opt-Out List.

Broker data derives from BADBOOL by Yael Grauer
(https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List, CC BY-NC-SA).

Workflow:
    python3 optout.py init          # one-time: enter your info -> me.toml
    python3 optout.py compose       # open Thunderbird compose windows for
                                    # every email-based opt-out
    python3 optout.py forms         # walk through web-form opt-outs in browser
    python3 optout.py status        # what's pending / sent / overdue
    python3 optout.py followup      # compose follow-ups for overdue requests

Requires Python 3.11+. Standard library only.
"""

import argparse
import json
import shlex
import shutil
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import webbrowser
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("This tool needs Python 3.11 or newer (for tomllib). "
             f"You are running {sys.version.split()[0]}.")

BASE = Path(__file__).resolve().parent
BROKERS_FILE = BASE / "brokers.json"
CONFIG_FILE = BASE / "me.toml"
STATE_FILE = BASE / "state.json"
OUTBOX = BASE / "outbox"
TEMPLATES = BASE / "templates"
UPSTREAM_RAW = ("https://raw.githubusercontent.com/yaelwrites/"
                "Big-Ass-Data-Broker-Opt-Out-List/master/README.md")

STATUSES = ("pending", "in-progress", "sent", "followup-sent",
            "done", "blocked", "na")
OPEN_STATUSES = ("pending", "in-progress")
AWAITING_STATUSES = ("sent", "followup-sent")
PRIORITY_ORDER = {"crucial": 0, "high": 1, "normal": 2}
PRIORITY_MARK = {"crucial": "***", "high": " **", "normal": "   "}
SUBJECT = "Data Deletion and Opt-Out Request"


# ---------------------------------------------------------------- data access

def load_brokers():
    if not BROKERS_FILE.exists():
        sys.exit(f"Missing {BROKERS_FILE.name} — it ships with this tool; "
                 "re-clone or restore it.")
    data = json.loads(BROKERS_FILE.read_text(encoding="utf-8"))
    brokers = data["brokers"]
    brokers.sort(key=lambda b: (PRIORITY_ORDER.get(b["priority"], 9),
                                b["name"].lower()))
    return data, brokers


def load_config():
    if not CONFIG_FILE.exists():
        sys.exit("No me.toml found. Run:  python3 optout.py init\n"
                 "(or copy me.example.toml to me.toml and edit it)")
    with CONFIG_FILE.open("rb") as f:
        cfg = tomllib.load(f)
    ident = cfg.get("identity", {})
    if not ident.get("full_name") or not ident.get("email"):
        sys.exit("me.toml must set identity.full_name and identity.email")
    return cfg


def load_state():
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            sys.exit(f"Could not read {STATE_FILE.name} ({exc}).\n"
                     "Restore it from a backup, or delete it to start "
                     "tracking from scratch.")
        if not isinstance(state.get("brokers"), dict):
            sys.exit(f"{STATE_FILE.name} does not look like this tool's "
                     "state file (no 'brokers' table). Move it aside to "
                     "start fresh.")
        return state
    return {"version": 1, "brokers": {}}


def save_state(state):
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(STATE_FILE)


def broker_state(state, broker_id):
    return state["brokers"].setdefault(
        broker_id, {"status": "pending", "history": [], "profile_url": None})


def record(state, broker_id, status=None, event=None, note=None):
    entry = broker_state(state, broker_id)
    if status:
        entry["status"] = status
    entry["history"].append({
        "date": date.today().isoformat(),
        "event": event or status,
        **({"note": note} if note else {}),
    })
    save_state(state)


def last_event_date(entry, events):
    for h in reversed(entry.get("history", [])):
        if h["event"] in events:
            return date.fromisoformat(h["date"])
    return None


# ------------------------------------------------------------ email building

def identity_block(cfg):
    ident, contact = cfg.get("identity", {}), cfg.get("contact", {})
    lines = [f"    Full name: {ident['full_name']}"]
    if ident.get("other_names"):
        lines.append(f"    Also appearing as: {'; '.join(ident['other_names'])}")
    addrs = contact.get("addresses", [])
    if addrs:
        lines.append(f"    Current address: {addrs[0]}")
        for a in addrs[1:]:
            lines.append(f"    Previous address: {a}")
    if contact.get("phones"):
        lines.append(f"    Phone number(s): {'; '.join(contact['phones'])}")
    emails = [ident["email"], *contact.get("old_emails", [])]
    lines.append(f"    Email address(es): {'; '.join(emails)}")
    if ident.get("dob"):
        lines.append(f"    Date of birth: {ident['dob']}")
    return "\n".join(lines)


def covers_clause(broker):
    covers = broker.get("covers") or []
    if not covers:
        return ""
    return " and its affiliated sites (" + ", ".join(covers) + ")"


def build_body(cfg, broker, profile_url, template="initial_request.txt",
               extra=None):
    path = TEMPLATES / template
    if not path.exists():
        sys.exit(f"Missing {path} — re-clone or restore the templates/ "
                 "directory.")
    text = path.read_text(encoding="utf-8")
    profile_block = ""
    if profile_url:
        profile_block = (f"\nMy listing appears at the following URL:\n"
                         f"    {profile_url}\n")
    fields = {
        "broker_name": broker["name"],
        "covers_clause": covers_clause(broker),
        "identity_block": identity_block(cfg),
        "profile_block": profile_block,
        "full_name": cfg["identity"]["full_name"],
        **(extra or {}),
    }
    return text.format(**fields)


def write_body_file(broker, body):
    OUTBOX.mkdir(exist_ok=True)
    path = OUTBOX / f"{broker['id']}.txt"
    path.write_text(body, encoding="utf-8")
    return path


# ------------------------------------------------------- broker selection

def pick(brokers, ids):
    by_id = {b["id"]: b for b in brokers}
    missing = [i for i in ids if i not in by_id]
    if missing:
        sys.exit("Unknown broker id(s): " + ", ".join(missing) +
                 "\nUse:  python3 optout.py list")
    return [by_id[i] for i in ids]


def email_capable(broker):
    return bool(broker.get("emails"))


def email_preferred(broker):
    return email_capable(broker) and broker.get("preferred_method") in (
        "email", "mixed")


def select_email_targets(brokers, state, ids, include_all):
    if ids:
        targets = pick(brokers, ids)
        not_email = [b["id"] for b in targets if not email_capable(b)]
        if not_email:
            sys.exit("No opt-out email address on file for: "
                     + ", ".join(not_email)
                     + "\nUse `forms` for form-based brokers.")
        return targets
    chooser = email_capable if include_all else email_preferred
    return [b for b in brokers if chooser(b) and not b.get("suspect")
            and broker_state(state, b["id"])["status"] in OPEN_STATUSES]


def ask_profile_url(broker, entry, assume_yes):
    if assume_yes:
        return entry.get("profile_url")
    prev = entry.get("profile_url")
    prompt = f"  Listing/profile URL on {broker['name']}"
    prompt += f" [{prev}]: " if prev else " (Enter to skip): "
    answer = input(prompt).strip()
    return answer or prev


# ------------------------------------------------------------- thunderbird

def thunderbird_cmd(cfg):
    binary = cfg.get("thunderbird", {}).get("binary") or "thunderbird"
    # A path with spaces ("C:\Program Files\...") is one executable; only
    # treat the value as a wrapper command ("flatpak run org...") when the
    # whole string doesn't resolve to a real program.
    if shutil.which(binary) or Path(binary).exists():
        parts = [binary]
    else:
        parts = shlex.split(binary) or [binary]
    if shutil.which(parts[0]) is None and not Path(parts[0]).exists():
        print(f"! Warning: '{parts[0]}' not found on PATH — set "
              "[thunderbird] binary in me.toml", file=sys.stderr)
    return parts


def compose_spec(to_addr, subject, body_file):
    # Thunderbird's -compose parser splits fields on commas and groups
    # values with single quotes, with no escape for a literal quote — so a
    # single quote anywhere in a value breaks the whole spec.
    for value in (to_addr, subject, str(body_file)):
        if "'" in value:
            sys.exit(f"Cannot pass {value!r} to thunderbird -compose: "
                     "it contains a single quote. Move this folder to a "
                     "path without quotes or use `eml`/`send` instead.")
    return (f"to='{to_addr}',subject='{subject}',"
            f"message='{body_file}'")


def launch_compose(cfg, broker, body_file, dry_run):
    to_addr = ",".join(broker["emails"])
    spec = compose_spec(to_addr, SUBJECT, body_file)
    cmd = [*thunderbird_cmd(cfg), "-compose", spec]
    if dry_run:
        print("  DRY RUN:", " ".join(f'"{c}"' if " " in c else c for c in cmd))
        return True
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        return True
    except OSError as exc:
        print(f"  ! Could not launch Thunderbird: {exc}", file=sys.stderr)
        return False


def pause_between_batches(count, batch_size):
    if batch_size > 0 and count % batch_size == 0:
        answer = input(f"\n-- {count} compose windows opened. Enter to "
                       "continue, q to stop here: ").strip().lower()
        if answer == "q":
            return False
    return True


# ------------------------------------------------------------------ commands

def cmd_init(args):
    if CONFIG_FILE.exists() and not args.force:
        sys.exit("me.toml already exists — edit it directly, or re-run "
                 "with --force to overwrite.")

    def ask(label, default=""):
        suffix = f" [{default}]" if default else ""
        val = input(f"{label}{suffix}: ").strip()
        return val or default

    def ask_list(label):
        print(f"{label} (one per line, empty line to finish):")
        items = []
        while True:
            val = input("  > ").strip()
            if not val:
                return items
            items.append(val)

    print("Only enter information the brokers ALREADY publish about you.\n")
    full_name = ask("Full name")
    if not full_name:
        sys.exit("A full name is required.")
    email = ask("Email address to send opt-outs from")
    if not email:
        sys.exit("An email address is required.")
    other_names = ask_list("Other names your listings appear under")
    addresses = ask_list("Addresses on your listings (current first)")
    phones = ask_list("Phone numbers on your listings")
    old_emails = ask_list("Old email addresses on your listings")
    tb = ask("Thunderbird command", "thunderbird")

    def t(value):  # TOML-safe string (JSON strings are valid TOML strings)
        return json.dumps(value, ensure_ascii=False)

    def tlist(values):
        return "[" + ", ".join(t(v) for v in values) + "]"

    CONFIG_FILE.write_text(f"""# Generated by optout.py init — edit freely.
# See me.example.toml for all options (SMTP sending, batch size, ...).

[identity]
full_name = {t(full_name)}
other_names = {tlist(other_names)}
email = {t(email)}

[contact]
addresses = {tlist(addresses)}
phones = {tlist(phones)}
old_emails = {tlist(old_emails)}

[preferences]
followup_days = 45

[thunderbird]
binary = {t(tb)}
batch_size = 5
""", encoding="utf-8")
    print(f"\nWrote {CONFIG_FILE}.\nNext:  python3 optout.py compose")


def cmd_list(args):
    _, brokers = load_brokers()
    state = load_state()
    shown = 0
    for b in brokers:
        entry = broker_state(state, b["id"])
        if args.status and entry["status"] != args.status:
            continue
        if args.method == "email" and not email_preferred(b):
            continue
        if args.method == "form" and email_preferred(b):
            continue
        if args.priority and b["priority"] != args.priority:
            continue
        method = "email" if email_preferred(b) else b["preferred_method"]
        mark = "! " if b.get("suspect") else ""
        print(f"{PRIORITY_MARK[b['priority']]} {b['id']:<28} "
              f"{method:<7} {entry['status']:<14} {mark}{b['name']}")
        shown += 1
    print(f"\n{shown} broker(s). *** = crucial, ** = high priority, "
          "! = suspect entry (see `show <id>`). "
          "Details:  python3 optout.py show <id>")


def cmd_show(args):
    _, brokers = load_brokers()
    state = load_state()
    for b in pick(brokers, args.ids):
        entry = broker_state(state, b["id"])
        print(f"\n=== {b['name']}  [{b['id']}]  "
              f"priority: {b['priority']}  status: {entry['status']}")
        if b.get("suspect"):
            print(f"    !! SUSPECT ENTRY: {b['suspect']}")
        if b.get("flags"):
            print("    flags:", ", ".join(b["flags"]))
        if b.get("search_url"):
            print("    find yourself:", b["search_url"])
        for url in b.get("optout_urls", []):
            print("    opt-out url:  ", url)
        for e in b.get("emails", []):
            print("    opt-out email:", e)
        for p in b.get("phones", []):
            print("    phone:        ", p)
        if b.get("covers"):
            print("    also removes: ", ", ".join(b["covers"]))
        print("    how:", b["instructions"])
        if b.get("notes"):
            print("    note:", b["notes"])
        for h in entry["history"]:
            print(f"    {h['date']}  {h['event']}"
                  + (f" — {h['note']}" if h.get("note") else ""))


def compose_flow(brokers, cfg, state, args, template, extra_for):
    """Shared driver for `compose` and `followup`."""
    batch_size = cfg.get("thunderbird", {}).get("batch_size", 5)
    opened = 0
    for b in brokers:
        entry = broker_state(state, b["id"])
        print(f"\n{b['name']}  ->  {', '.join(b['emails'])}")
        if b.get("notes"):
            print(f"  note: {b['notes']}")
        profile_url = ask_profile_url(b, entry, args.yes)
        if profile_url:
            entry["profile_url"] = profile_url
            save_state(state)
        body = build_body(cfg, b, profile_url, template, extra_for(b))
        body_file = write_body_file(b, body)
        if not launch_compose(cfg, b, body_file, args.dry_run):
            continue
        opened += 1
        if args.dry_run:
            continue
        status = "followup-sent" if template.startswith("followup") else "sent"
        if args.yes or not input(
                "  Mark as sent once you hit Send? [Y/n]: "
                ).strip().lower().startswith("n"):
            record(state, b["id"], status=status, event=status)
        if not args.yes and not pause_between_batches(opened, batch_size):
            break
    print(f"\n{opened} compose window(s) {'planned' if args.dry_run else 'opened'}. "
          f"Bodies saved under {OUTBOX}/")


def cmd_compose(args):
    cfg = load_config()
    _, brokers = load_brokers()
    state = load_state()
    targets = select_email_targets(brokers, state, args.ids, args.all_email)
    if not targets:
        print("Nothing to compose — no pending email-based brokers. "
              "Try `--all-email`, or `forms` for the rest.")
        return
    print(f"{len(targets)} email opt-out(s) to compose. For each one: "
          "review the window Thunderbird opens, then press Send.")
    compose_flow(targets, cfg, state, args, "initial_request.txt",
                 lambda b: None)


def cmd_followup(args):
    cfg = load_config()
    _, brokers = load_brokers()
    state = load_state()
    due_days = cfg.get("preferences", {}).get("followup_days", 45)
    today = date.today()
    if args.ids:
        for b in pick(brokers, args.ids):
            if not email_capable(b):
                sys.exit(f"{b['id']} has no opt-out email address — "
                         "follow-ups only work for email-based requests.")
    targets, extras = [], {}
    for b in brokers:
        if not email_capable(b):
            continue
        entry = broker_state(state, b["id"])
        if entry["status"] not in AWAITING_STATUSES:
            continue
        sent = last_event_date(entry, ("sent", "followup-sent"))
        if not sent:
            continue
        days = (today - sent).days
        if days >= due_days or (args.ids and b["id"] in args.ids):
            targets.append(b)
            extras[b["id"]] = {"sent_date": sent.isoformat(),
                               "days_since": str(days)}
    if args.ids:
        targets = [b for b in targets if b["id"] in args.ids]
    if not targets:
        print(f"No email requests older than {due_days} days without a "
              "confirmation. Nothing to follow up.")
        return
    print(f"{len(targets)} overdue request(s).")
    compose_flow(targets, cfg, state, args, "followup_request.txt",
                 lambda b: extras[b["id"]])


def cmd_forms(args):
    cfg = load_config()
    _, brokers = load_brokers()
    state = load_state()
    targets = (pick(brokers, args.ids) if args.ids else
               [b for b in brokers
                if not email_preferred(b) and not b.get("suspect")
                and broker_state(state, b["id"])["status"] in OPEN_STATUSES])
    if not targets:
        print("No pending form-based brokers. See `status`.")
        return
    print(f"{len(targets)} form-based opt-out(s). For each: a browser tab "
          "opens, follow the steps shown here, then mark the result.\n"
          "Keys: [d]one  [s]ent/awaiting-confirmation  [p]ostpone  "
          "[b]locked  [n]/a (no listing)  [q]uit")
    for b in targets:
        entry = broker_state(state, b["id"])
        print(f"\n=== {b['name']}  ({b['priority']}"
              + (", " + ", ".join(b["flags"]) if b.get("flags") else "") + ")")
        if b.get("suspect"):
            print(f"  !! SUSPECT ENTRY: {b['suspect']}")
            if input("  This may not be a real data broker. Open its pages "
                     "anyway? [y/N]: ").strip().lower() != "y":
                continue
        print("  " + b["instructions"])
        if b.get("notes"):
            print(f"  note: {b['notes']}")
        for url in ([b["search_url"]] if b.get("search_url") else []) \
                + b.get("optout_urls", []):
            print(f"  opening: {url}")
            webbrowser.open(url)
        while True:
            key = input("  result [d/s/p/b/n/q]: ").strip().lower()
            if key in ("d", "s", "p", "b", "n", "q", ""):
                break
        if key == "q":
            break
        status = {"d": "done", "s": "sent", "b": "blocked", "n": "na",
                  "p": None, "": None}[key]
        if status:
            note = input("  note (optional): ").strip() or None
            record(state, b["id"], status=status, event=status, note=note)
    print("\nProgress saved. Resume any time with `forms`.")


def cmd_mark(args):
    _, brokers = load_brokers()
    state = load_state()
    for b in pick(brokers, args.ids):
        record(state, b["id"], status=args.to, event=args.to, note=args.note)
        print(f"{b['id']} -> {args.to}")


def cmd_status(args):
    cfg = load_config() if CONFIG_FILE.exists() else {}
    _, brokers = load_brokers()
    state = load_state()
    due_days = cfg.get("preferences", {}).get("followup_days", 45)
    counts = {}
    overdue, awaiting = [], []
    today = date.today()
    for b in brokers:
        entry = broker_state(state, b["id"])
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
        if entry["status"] in AWAITING_STATUSES:
            sent = last_event_date(entry, ("sent", "followup-sent"))
            days = (today - sent).days if sent else 0
            (overdue if days >= due_days else awaiting).append((b, days))
    total = len(brokers)
    done = counts.get("done", 0) + counts.get("na", 0)
    print(f"Progress: {done}/{total} closed out "
          f"({counts.get('done', 0)} done, {counts.get('na', 0)} n/a)")
    for status in STATUSES:
        if counts.get(status):
            print(f"  {status:<14} {counts[status]}")
    suspect = [b["id"] for b in brokers if b.get("suspect")]
    if suspect:
        print(f"\n{len(suspect)} suspect entries excluded from automation "
              f"({', '.join(suspect)}) — see `show <id>`.")
    if awaiting:
        print("\nAwaiting confirmation:")
        for b, days in awaiting:
            print(f"  {b['id']:<28} sent {days} day(s) ago")
    if overdue:
        print(f"\nOVERDUE (> {due_days} days, no confirmation):")
        for b, days in overdue:
            hint = ("followup" if email_capable(b)
                    else f"re-check the listing: forms {b['id']}")
            print(f"  {b['id']:<28} sent {days} day(s) ago — {hint}")
        if any(email_capable(b) for b, _ in overdue):
            print("  Run `python3 optout.py followup` for the email-based "
                  "ones.")
    nxt = next((b for b in brokers
                if not b.get("suspect")
                and broker_state(state, b["id"])["status"] in OPEN_STATUSES),
               None)
    if nxt:
        method = "compose" if email_preferred(nxt) else "forms"
        print(f"\nNext up: {nxt['name']} ({nxt['priority']}) — "
              f"python3 optout.py {method} {nxt['id']}")


def cmd_eml(args):
    cfg = load_config()
    _, brokers = load_brokers()
    state = load_state()
    targets = select_email_targets(brokers, state, args.ids, args.all_email)
    if not targets:
        print("No pending email-based brokers.")
        return
    OUTBOX.mkdir(exist_ok=True)
    for b in targets:
        entry = broker_state(state, b["id"])
        profile_url = ask_profile_url(b, entry, args.yes)
        if profile_url:
            entry["profile_url"] = profile_url
            save_state(state)
        msg = EmailMessage()
        msg["From"] = cfg["identity"]["email"]
        msg["To"] = ", ".join(b["emails"])
        msg["Subject"] = SUBJECT
        msg["Date"] = formatdate(localtime=True)
        msg["X-Unsent"] = "1"
        msg.set_content(build_body(cfg, b, profile_url))
        path = OUTBOX / f"{b['id']}.eml"
        path.write_bytes(msg.as_bytes())
        print(f"wrote {path}")
    print("\nIn Thunderbird: open a .eml (Ctrl+O), then press Ctrl+E "
          "('Edit As New Message') to get a sendable draft.")


def cmd_mailto(args):
    cfg = load_config()
    _, brokers = load_brokers()
    state = load_state()
    targets = select_email_targets(brokers, state, args.ids, args.all_email)
    if not targets:
        print("No pending email-based brokers.")
        return
    rows = []
    for b in targets:
        # mailto: URLs get truncated by OSes/browsers past ~2000 chars, so
        # links carry a condensed request; the full letter comes via
        # `compose`/`eml`. RFC 6068 wants CRLF line breaks.
        profile_url = broker_state(state, b["id"]).get("profile_url")
        body = (
            "To Whom It May Concern,\n\n"
            f"Please delete my personal information from {b['name']}"
            f"{covers_clause(b)}, add me to your suppression list, and opt "
            "me out of any sale or sharing of my personal information, as "
            "provided by the California Consumer Privacy Act and equivalent "
            "state privacy laws. The information concerned relates to:\n\n"
            + identity_block(cfg) + "\n"
            + (f"\nMy listing: {profile_url}\n" if profile_url else "")
            + "\nPlease confirm completion in writing to this address.\n\n"
            f"Thank you,\n{cfg['identity']['full_name']}\n")
        href = ("mailto:" + ",".join(b["emails"])
                + "?subject=" + urllib.parse.quote(SUBJECT)
                + "&body=" + urllib.parse.quote(body.replace("\n", "\r\n")))
        if len(href) > 1900:
            print(f"! {b['id']}: mailto link is {len(href)} chars; some "
                  "systems truncate past ~2000 — prefer `compose` or `eml` "
                  "for this one.")
        rows.append(f'<li><a href="{href}">{b["name"]}</a> '
                    f'<small>{", ".join(b["emails"])}</small></li>')
    page = ("<!doctype html><meta charset='utf-8'>"
            "<title>Opt-out emails</title>"
            "<h1>Data broker opt-out emails</h1>"
            "<p>Each link opens a pre-filled message in your default mail "
            "client (set Thunderbird as default). These use a condensed "
            "request — <code>compose</code> and <code>eml</code> produce "
            "the full letter. After sending, run "
            "<code>python3 optout.py mark &lt;id&gt; sent</code>.</p>"
            "<ol>" + "".join(rows) + "</ol>")
    out = BASE / "mailto.html"
    out.write_text(page, encoding="utf-8")
    print(f"wrote {out} — open it in your browser.")


def cmd_send(args):
    import getpass
    import os
    import smtplib

    cfg = load_config()
    smtp_cfg = cfg.get("smtp", {})
    host = smtp_cfg.get("host")
    if not host:
        sys.exit("Set [smtp] host/port/username/from_addr in me.toml first "
                 "(copy them from Thunderbird's Outgoing Server settings), "
                 "or use `compose` to send through Thunderbird itself.")
    _, brokers = load_brokers()
    state = load_state()
    targets = select_email_targets(brokers, state, args.ids, args.all_email)
    if not targets:
        print("No pending email-based brokers.")
        return
    print("About to send directly via SMTP (no review window!):")
    for b in targets:
        print(f"  {b['id']:<28} -> {', '.join(b['emails'])}")
    if not args.yes and input(
            f"Send {len(targets)} email(s) now? [y/N]: ").strip().lower() != "y":
        print("Aborted.")
        return
    username = smtp_cfg.get("username") or cfg["identity"]["email"]
    password = os.environ.get("OPTOUT_SMTP_PASSWORD") or getpass.getpass(
        f"SMTP password for {username}: ")
    port = smtp_cfg.get("port", 587)
    context = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=60, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=60)
    with server:
        if port != 465:
            server.starttls(context=context)
        server.login(username, password)
        for b in targets:
            entry = broker_state(state, b["id"])
            msg = EmailMessage()
            msg["From"] = smtp_cfg.get("from_addr") or cfg["identity"]["email"]
            msg["To"] = ", ".join(b["emails"])
            msg["Subject"] = SUBJECT
            msg["Date"] = formatdate(localtime=True)
            msg["Message-ID"] = make_msgid()
            msg.set_content(build_body(cfg, b, entry.get("profile_url")))
            server.send_message(msg)
            record(state, b["id"], status="sent", event="sent",
                   note="via SMTP")
            print(f"sent: {b['id']}")
            time.sleep(2)  # be gentle with the relay


def cmd_check_upstream(args):
    data, _ = load_brokers()
    print(f"Fetching {UPSTREAM_RAW} ...")
    with urllib.request.urlopen(UPSTREAM_RAW, timeout=60) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    seen = [line.strip() for line in text.splitlines()
            if line.startswith("### ") or line.startswith("## ")]
    known = data.get("source_headings", [])
    added = [h for h in seen if h not in known]
    removed = [h for h in known if h not in seen]
    if not added and not removed:
        print("brokers.json is in sync with the upstream list.")
        return
    for h in added:
        print(f"  NEW upstream:     {h}")
    for h in removed:
        print(f"  GONE upstream:    {h}")
    print("\nThe upstream list changed — check "
          "https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List "
          "and update brokers.json accordingly.")


# ---------------------------------------------------------------------- main

def add_target_args(p, all_email=True, yes=True):
    p.add_argument("ids", nargs="*", help="broker id(s); default: all "
                   "pending email-based brokers")
    if all_email:
        p.add_argument("--all-email", action="store_true",
                       help="include brokers where email is a fallback, not "
                            "the primary route")
    if yes:
        p.add_argument("--yes", "-y", action="store_true",
                       help="no per-broker prompts")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="optout.py",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Start with:  optout.py init  ->  compose  ->  forms  ->  "
               "status  ->  followup")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="interactively create me.toml")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("list", help="list brokers and status")
    p.add_argument("--status", choices=STATUSES)
    p.add_argument("--method", choices=("email", "form"))
    p.add_argument("--priority", choices=("crucial", "high", "normal"))
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="full details for broker id(s)")
    p.add_argument("ids", nargs="+")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("compose",
                       help="open Thunderbird compose windows (email brokers)")
    add_target_args(p)
    p.add_argument("--dry-run", action="store_true",
                   help="print the thunderbird commands instead of running")
    p.set_defaults(func=cmd_compose)

    p = sub.add_parser("followup",
                       help="compose follow-ups for overdue requests")
    add_target_args(p, all_email=False)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_followup)

    p = sub.add_parser("forms",
                       help="walk through form-based opt-outs in the browser")
    p.add_argument("ids", nargs="*")
    p.set_defaults(func=cmd_forms)

    p = sub.add_parser("eml", help="write .eml drafts to outbox/")
    add_target_args(p)
    p.set_defaults(func=cmd_eml)

    p = sub.add_parser("mailto", help="write mailto.html with pre-filled links")
    add_target_args(p, yes=False)
    p.set_defaults(func=cmd_mailto)

    p = sub.add_parser("send", help="send directly via SMTP (no review!)")
    add_target_args(p)
    p.set_defaults(func=cmd_send)

    p = sub.add_parser("mark", help="set a broker's status")
    p.add_argument("ids", nargs="+")
    p.add_argument("to", choices=STATUSES)
    p.add_argument("--note")
    p.set_defaults(func=cmd_mark)

    p = sub.add_parser("status", help="progress dashboard + overdue requests")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("check-upstream",
                       help="diff brokers.json against the live BADBOOL list")
    p.set_defaults(func=cmd_check_upstream)

    args = ap.parse_args(argv)
    try:
        args.func(args)
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted — progress already made was saved.")
        sys.exit(130)


if __name__ == "__main__":
    main()
