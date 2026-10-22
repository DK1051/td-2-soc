# Incident report INC-XX: <short title>

Copy this file to `2e-blind-hunt/reports/INC-01.md` (then 02 ... 05), one report per suspected
account takeover. Write in plain words: a manager who is not technical should follow it.

## What happened
Two or three sentences. Who is the affected account (user and job title)? What was done to it,
and when did it start and end?

## Timeline
One line per step, in time order (times in UTC, copied from the data):

| Time (UTC) | What happened | Event id (CorrelationId) |
|---|---|---|
| | | |

## Evidence rows
Paste the exact data rows (sign-in and audit) that prove each step, or say which file and line
they are on. Say what in the row makes it unusual for THIS user (new device? new country?
no callback note?).

## Why this is a takeover and not a look-alike
What did you check to rule out the harmless explanations (travelling, new hire, VPN, lost
phone with a proper callback)? What would have made you change your mind?

## Impact
What could the person who got in see or change with this account? Did they touch anything
privileged (roles, recovery email, the Core Banking Admin app)?

## Containment recommended
What should be done now, in order (for example: block sign-in, revoke sessions, reset the
password through a verified call, remove the new MFA method, undo the role or recovery email
change, check what the account did after the last event)?

## What the helpdesk should have asked
Which question or check, before resetting this password, would have stopped it? Write it as a
short script the helpdesk agent could use.
