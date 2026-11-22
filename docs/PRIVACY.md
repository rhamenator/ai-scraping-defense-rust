# Privacy and IP addresses

This page explains what personal data this edition stores, how to configure its handling, and what to take to a lawyer.
It describes the software's behaviour. It is not legal advice, and the project does not make compliance decisions for
you.

## Who is responsible

The people who run a deployment (the operators) decide why and how visitors' data is processed, so under data-protection
law they are the controllers. The project provides the software and the settings below. Which settings fit depends on
where you operate, who your visitors are, and your own legal advice, which is why none of this is hard-coded.

## What is stored, and where

The only personal data this edition holds about a visitor is the IP address they connected from.

| Where | What | Removed by |
| --- | --- | --- |
| Blocklist and flag entries (memory, Redis) | the address, a reason, an expiry (`BLOCKLIST_TTL_SECONDS`, default 24 hours) | expiry, `POST /unblock`, erasure |
| Security events, `actor` column | the address, for events emitted by the tarpit, AI service and escalation engine | erasure, retention |
| Security events, `payload` | the address, in events such as `admin_block_ip` | erasure, retention |
| Erasure request records | a hash of the address, never the address | kept as evidence |
| Log files, backups, other services' Redis keys (for example tarpit hop counters) | possibly the address | **not covered**; handle them under your own policy |

## Settings

| Setting | Default | Effect |
| --- | --- | --- |
| `GDPR_ERASURE_MODE` | `redact` | `redact` replaces the address with `[erased]` in stored events and keeps the events; `delete` removes them; `manual` only records the request. |
| `GDPR_ACTIVE_BLOCK_POLICY` | `retain_until_expiry` | An active block is kept until it expires (the answer says when), or `erase_now` removes it at once. |
| `GDPR_HASH_KEY` | unset | Makes the hash in request records a keyed HMAC-SHA256 that only your deployment can reproduce. Unset, it is a plain SHA-256, which is only a pseudonym: all IPv4 addresses can be tried in minutes. |
| `AUDIT_RETENTION_DAYS` | `0` (keep everything) | Above zero, security events older than that are deleted daily. Erasure records are kept. |
| `AUDIT_STORAGE_BACKEND` | `auto` | Use `postgres` when more than one service writes events. A JSONL file shared by several services is protected by a file lock, but a database is the better fit. |

Two stricter profiles you might start from, to adjust with your own advice:

- **Minimise:** `GDPR_ERASURE_MODE=delete`, `GDPR_ACTIVE_BLOCK_POLICY=erase_now`, `AUDIT_RETENTION_DAYS=30`, `GDPR_HASH_KEY` set.
- **Security first:** the defaults, plus a retention period you can justify.

## Points to settle with your own advice

- **An IP address is personal data** in EU law (the Court of Justice has said so for dynamic addresses). Storing it is
  processing that needs a lawful basis. For blocking abusive scrapers and attackers, operators commonly rely on
  legitimate interest in network security, and should write down why the interest outweighs the visitor's.
- **Reverse DNS does not anonymise.** Many consumer ISPs publish hostnames that embed the address
  (`c-203-0-113-7.hsd1.example.net`), so a hostname identifies the connection just as well as the address does.
- **Hashing does not remove the data from scope.** A salted or keyed hash of an address is still personal data
  (pseudonymised), and keeping the raw address alongside its hash adds no protection to the raw address. Hashing only
  reduces exposure if the raw address is not kept. Matching by hash is possible in principle, because an incoming
  address can be hashed with the same key and compared, but this edition does not do that.
- **Storage limitation.** Keeping addresses indefinitely is the hardest thing to justify. `AUDIT_RETENTION_DAYS` exists
  so the period is your decision, and it is off by default only because that decision is yours.
- **Where the law applies.** EU rules can apply to an operator outside the EU who monitors the behaviour of people in
  the EU, and apply directly to operators inside it. Whether and how that is enforced against a particular operator is a
  question for a lawyer in the relevant jurisdictions, not something this project can promise either way.
- **Erasure requests have exceptions** (for example legal claims and, arguably, active security measures), and an IP
  address is weak proof of identity. The `retain_until_expiry` and `manual` settings exist for those cases.
- **Your own paperwork:** a privacy notice, a record of your lawful basis, and how a visitor reaches you. The software
  cannot supply those.
