# MikroTik blocking report

A small Python 3 collector polls RouterOS over its HTTPS REST API and saves IPv4
drop-rule counters in a local SQLite database. Separate commands email summaries
for completed Monday-to-Monday weeks and calendar months through a configured
mail transport helper; an interactive command renders explicit historical
date ranges to stdout. Install it on any Linux host that can reach the router;
no server names or credentials are built into the program.

The `run` command provides the same collection and report-check workflows as
one long-lived foreground process for service managers and containers. The
existing one-shot commands and systemd timers remain supported.

The two report sections have different meanings. The local rule measures packets
discarded by the router's own detection list. Bouncer rules measure traffic
discarded under CrowdSec decisions; CrowdSec detects and classifies those
attacks. Counts are packets and bytes, not unique IPs or attacks. The collector
also records one lightweight event when the local detection rule first adds a
source to the configured list. Destination-port rankings count those detection
events, while recurring-source rankings group the same events by source IP.
Neither ranking measures packets, unique sources, or confirmed attacks. The
collector never enables per-packet drop logging.

## Requirements and configuration

* Python 3.10 or newer, with timezone data for `MIKROTIK_REPORT_TIMEZONE`.
* RouterOS 7.20 or newer with `www-ssl` enabled, a certificate trusted by the
  collecting host, and a dedicated account permitted to read firewall rules,
  address lists, system resource data, and the dedicated log buffer. On the
  tested RouterOS 7.24.4 installation, a custom group with
  `read,api,rest-api` worked; `read,rest-api` alone returned
  `not allowed (9)`. Restrict the account to the collecting host with its
  `address` setting (for example `192.0.2.10/32`; replace it with the
  actual collector address).
* An external mail transport helper configured with the absolute
  `MIKROTIK_REPORT_NOTIFIER` path. The helper may live anywhere on the
  collecting host and is responsible for its own transport configuration.

Copy `.env.example` to a private `.env` and adapt every required value.
`MIKROTIK_REPORT_NOTIFIER` must be an absolute path; keeping the mail helper
outside this project does not require any particular repository layout. The
example selects the local `raw` rule by exact comment and source address list.
Change `MIKROTIK_LOCAL_RULE_TABLE` to `filter` if the local drop rule is there.
The bouncer selector matches the configured signature within a rule comment,
the configured source address list, and `action=drop` in both IPv4 `raw` and
`filter` tables. This includes only source blocking, not output-chain rules
using a destination list. An absent bouncer rule contributes zero until it
returns. The local rule must match exactly once; missing or duplicate local
rules make collection fail so a bad selector cannot silently report zero.

`MIKROTIK_REST_URL` must be an HTTPS URL ending in `/rest`. TLS verification
remains enabled. For a private CA, set `MIKROTIK_CA_FILE` to its PEM bundle or
install it in the system trust store. The collector makes six small read-only
requests per run: IPv4 `raw` rules, IPv4 `filter` rules, each selected address
list, router uptime, and the dedicated detection-event memory log. Rule, list,
and log responses request only needed fields. The list requests return one
minimal record per entry to determine their size.

ASN enrichment for source IPs is disabled by default. Set
`MIKROTIK_ASN_ENABLED=true` to resolve newly persisted source IPs through Team
Cymru's community bulk WHOIS service at `whois.cymru.com:43`. The collector
sends all pending IPs in one connection with a five-second timeout. It commits
RouterOS counters and detection aggregates before making that optional request,
so an unavailable or malformed ASN response cannot roll back or fail traffic
collection. Enabling this requires outbound TCP port 43 from the collecting
host. WHOIS uses unencrypted TCP, so enabling this option discloses the queried
source IPs to Team Cymru and network operators on that path; confirm that this
fits the deployment's privacy policy. No ASN connection is attempted while the
option is disabled.

Each collection hydrates at most `MIKROTIK_ASN_BATCH_SIZE` due entries (default
`100`), so enabling enrichment with historical source IPs drains the backlog
gradually. Failed or unmapped entries retry with exponential backoff beginning
at `MIKROTIK_ASN_RETRY_BASE_SECONDS` (default `3600`) and capped by
`MIKROTIK_ASN_RETRY_MAX_SECONDS` (default `86400`). Successful metadata becomes
eligible for refresh after `MIKROTIK_ASN_REFRESH_DAYS` (default `30`). These
values must be positive, and the maximum retry interval cannot be less than the
base interval.

Use an absolute `MIKROTIK_REPORT_DB` path outside the checkout. The SQLite
database contains last counter values, current/pending weekly totals, the last
12 successfully emailed weekly aggregates, and daily aggregates for exact month
boundaries and later historical queries. Monthly delivery status is stored in
the same database. Daily destination-port counts, daily source-IP detection
counts, and a bounded cursor of the RouterOS memory entries seen during the
previous poll are also stored. ASN metadata is normalized into one row per
source IP rather than copied into historical samples. Each row records the ASN,
organization, successful metadata update time, latest attempt time, next retry
time, retry count, and latest error. Failed or unmapped lookups retain the
source IP and are retried by later collector runs when due. A failed refresh
keeps the last successful metadata available to reports. Source IPs are retained
only as aggregate keys; full firewall messages,
destination addresses, interfaces, MAC addresses, and packet lengths are not
retained. The schema uses SQLite's
`user_version`; a writing command
upgrades an older unversioned database before changing report state, while a
database created by a newer unsupported version is rejected. Daily aggregates
are retained without a time limit; they are small and contain no raw RouterOS
responses or individual samples. Existing weeks recorded before this feature
cannot be reconstructed into daily history.
The service user needs write access to its parent directory. The program sets
the database file to mode `600`. Keep `.env` private as it contains the RouterOS
password; neither it nor the database belongs in Git.

The persistent `run` mode uses three explicit positive-integer intervals:
`MIKROTIK_COLLECT_INTERVAL_SECONDS` (default `300`),
`MIKROTIK_WEEKLY_CHECK_INTERVAL_SECONDS` (default `86400`), and
`MIKROTIK_MONTHLY_CHECK_INTERVAL_SECONDS` (default `86400`). These intervals
control when the existing workflows are checked; weekly and monthly report
boundaries still use calendar periods in `MIKROTIK_REPORT_TIMEZONE`.

## Upgrading from v0.1.0

Version `0.1.1` adds optional ASN enrichment and advances SQLite
`user_version` from `3` to `5`. Stop all collectors and report processes, then
back up the SQLite database before upgrading. The first writing command after
the upgrade performs the migration atomically, retains existing counter and
detection history, and queues previously observed source IPs for gradual ASN
hydration. ASN enrichment remains disabled unless `MIKROTIK_ASN_ENABLED=true`
is added to the environment.

After the database has migrated, `v0.1.0` will reject the newer schema. Restore
the pre-upgrade backup if a rollback is required; do not downgrade the
`user_version` manually. Existing historical detections are joined to the
latest persisted ASN metadata for their source IP. ASN refreshes can therefore
change the ASN attribution shown when the same historical range is rendered
later; the application does not retain point-in-time ASN assignments.

## RouterOS detection-event setup

Destination-port rankings use a dedicated in-memory RouterOS log buffer. Do not
enable logging on the `local-detections` drop rule: it matches every subsequent
packet and would create the per-packet logging this component is designed to
avoid. Instead, enable logging only on the rule that initially detects a source
and performs `add-src-to-address-list`. That rule must stop matching the source
after adding it, normally through `src-address-list=!local-detections` or an
equivalent condition.

Create a dedicated memory buffer and route only messages with the configured
prefix into it. These commands use the defaults from `.env.example`:

```routeros
/system/logging/action/add name=mikrotik-report target=memory memory-lines=1000
/system/logging/add action=mikrotik-report topics=firewall regex="^mikrotik-report-detect"
```

Locate and inspect the detection rule before changing it. Adapt `raw` to
`filter` if that is where the rule lives:

```routeros
/ip/firewall/raw/print detail where action=add-src-to-address-list and address-list="local-detections"
```

After confirming that the rule represents the first detection rather than the
drop path, enable its log flag using the exact rule ID printed above:

```routeros
/ip/firewall/raw/set *RULE_ID log=yes log-prefix="mikrotik-report-detect"
```

Verify that a test detection produces a single entry with protocol, source and
destination ports:

```routeros
/log/print where buffer=mikrotik-report
```

Set `MIKROTIK_DETECTION_LOG_BUFFER` and `MIKROTIK_DETECTION_LOG_PREFIX` if other
names are used. Keep the buffer in memory rather than on router flash. The
router clock must be synchronized and use the same timezone as
`MIKROTIK_REPORT_TIMEZONE`, because current-day RouterOS log entries contain
only a local time.

The first successful collector run establishes a conservative cursor over the
existing buffer and does not claim those older entries. Later polls store only
new matching TCP/UDP events as daily `protocol/destination-port` counts and
daily source-IP detection counts. The cursor contains hashes for at most the
entries in the current memory buffer; it does not grow with report history. A
router reboot or buffer overflow before a poll can lose detection events, and
those events cannot be reconstructed from firewall counters. An empty ranking
therefore means no events were persisted, not proof that no detections occurred.

## Persistent run mode

Start all periodic work in one foreground process with the complete environment
configured:

```bash
cd /path/to/mikrotik-report
python3 mikrotik_report.py run
```

Collection, the weekly report check, and the monthly report check each run once
at startup, sequentially in that order. They then run at their configured
independent intervals. Jobs never overlap inside the process; if a workflow
runs past one or more of its deadlines, those missed invocations are skipped
instead of being started concurrently. The next report check still processes
all pending completed periods from SQLite.

`SIGINT` and `SIGTERM` request a clean stop. An in-progress workflow is allowed
to finish before the process exits. Operational failures remain visible and
cause a non-zero exit so a service manager can apply its restart policy. Do not
run this mode alongside the timer deployment below, because both provide the
same scheduling role.

## Container image

Release images are published to GitHub Container Registry. Pull the current
stable release with:

```bash
docker pull ghcr.io/raposo93/mikrotik-report:latest
```

Each GitHub release also publishes full-version and moving major/minor tags,
for example `1.2.3` and `1.2`. Prereleases receive version tags but do not
replace `latest`.

To build the standalone image locally from the repository root instead:

```bash
docker build -t mikrotik-report:local .
```

The image uses the explicit `python:3.12.14-slim-bookworm` base and runs
`mikrotik_report.py run` directly as UID and GID `10001`. Python is therefore
the foreground process and receives Docker's `SIGTERM` shutdown signal. The
image contains no `.env`, credentials, SQLite state, tests, systemd units, mail
server, or mail transport helper.

Create a private environment file outside the checkout from `.env.example`.
The variables required by `run` are:

* state: `MIKROTIK_REPORT_DB`;
* RouterOS access: `MIKROTIK_REST_URL`, `MIKROTIK_USER`, `MIKROTIK_PASSWORD`,
  `MIKROTIK_LOCAL_RULE_COMMENT`, `MIKROTIK_LOCAL_LIST`,
  `MIKROTIK_CROWDSEC_RULE_SIGNATURE`, and `MIKROTIK_CROWDSEC_LIST`;
* mail delivery: `MIKROTIK_REPORT_TO` and `MIKROTIK_REPORT_NOTIFIER`.

The timezone, rule table, detection-log names, ASN enrichment policy, report
subjects, mail account and sender, CA bundle, and scheduling intervals are
optional or have documented defaults in `.env.example`. Keep the database at
the declared persistent path and point the notifier at a separately mounted
compatible executable:

```text
MIKROTIK_REPORT_DB=/var/lib/mikrotik-report/report.sqlite3
MIKROTIK_REPORT_NOTIFIER=/usr/local/bin/send-mail
```

Run the image with a named volume for the only persistent application state and
mount the configured mail helper read-only:

```bash
docker volume create mikrotik-report-data
docker run --rm --name mikrotik-report \
  --env-file /absolute/path/to/mikrotik-report.env \
  --mount type=volume,src=mikrotik-report-data,dst=/var/lib/mikrotik-report \
  --mount type=bind,src=/absolute/path/to/send-mail,dst=/usr/local/bin/send-mail,readonly \
  ghcr.io/raposo93/mikrotik-report:latest
```

The mail helper and any files it needs must be executable/readable by UID
`10001`; the image does not assume a specific helper implementation or SMTP
client. A bind-mounted state directory must likewise be writable by UID/GID
`10001`. A private RouterOS CA bundle can be mounted read-only and selected with
`MIKROTIK_CA_FILE`. Logs remain on stdout and stderr. Stop the container with
`docker stop` or `Ctrl-C`; the persistent mode completes any active workflow and
then exits cleanly. Do not run the container scheduler alongside the host timer
deployment against the same database.

### Docker Compose example

`compose.example.yaml` is a generic deployment example that can stay in this
repository or be copied into a separate deployment repository. It uses the
published `ghcr.io/raposo93/mikrotik-report:latest` image by default. Set
`MIKROTIK_REPORT_IMAGE` to pin a version or use a locally built image.

Copy `.env.example` to a private `.env` beside the Compose file and keep the
container paths shown above for the database and notifier. Export the absolute
host path of the compatible notifier, then start the service:

```bash
export MIKROTIK_REPORT_NOTIFIER_HOST_PATH=/absolute/path/to/send-mail
docker compose -f compose.example.yaml up -d
```

Set `MIKROTIK_REPORT_ENV_FILE` if the private application environment file has
another name or location. Compose creates the `report-data` named volume for
SQLite and preserves it across container replacement. The notifier is mounted
read-only at `/usr/local/bin/send-mail`. The example applies
`restart: unless-stopped`, gives an active workflow up to one minute to finish
after a stop request, and publishes no inbound ports. It contains no RouterOS,
SMTP, monitoring, update, or database sidecars.

## Installation with systemd timers

The templates are examples; replace `/path/to/mikrotik-report` and `YOUR_USER`
in all three services. Choose a user that can read `.env` and write the state
directory.
The collector's `StateDirectory=mikrotik-report` creates
`/var/lib/mikrotik-report` for `MIKROTIK_REPORT_DB`. Configure the mail helper
and its credential access before enabling the report timers. The weekly and
monthly services run as the same unprivileged user. If the chosen mail helper
requires an additional group or another local permission, add it with a
site-specific systemd drop-in rather than editing the portable templates. The
report services have no `StateDirectory` so systemd does not change ownership
of the collector's directory. Set the timezone in `.env` to the intended
reporting timezone, for example `Etc/UTC`.
If a report timer runs before the first collection, it exits without creating
the database; the collector creates it under its own user.

```bash
cd /path/to/mikrotik-report
cp .env.example .env
chmod 600 .env
# Edit .env and all service templates for this host.
sudo install -m 644 mikrotik-report-collect.service.example /etc/systemd/system/mikrotik-report-collect.service
sudo install -m 644 mikrotik-report-collect.timer.example /etc/systemd/system/mikrotik-report-collect.timer
sudo install -m 644 mikrotik-report-weekly.service.example /etc/systemd/system/mikrotik-report-weekly.service
sudo install -m 644 mikrotik-report-weekly.timer.example /etc/systemd/system/mikrotik-report-weekly.timer
sudo install -m 644 mikrotik-report-monthly.service.example /etc/systemd/system/mikrotik-report-monthly.service
sudo install -m 644 mikrotik-report-monthly.timer.example /etc/systemd/system/mikrotik-report-monthly.timer
sudo systemctl daemon-reload
sudo systemctl enable --now mikrotik-report-collect.timer mikrotik-report-weekly.timer mikrotik-report-monthly.timer
```

For an existing installation where a report unit runs as `root`, update the
installed unit to match the template while preserving its local user, paths,
and any helper-specific permissions in a local drop-in, then run
`sudo systemctl daemon-reload`. The collector unit and database ownership stay
with the collector user.

The collector timer first runs two minutes after boot, then five minutes after
each activation. The weekly timer checks at 00:15 and the monthly timer at 00:30
every day in the host's local timezone. Both have `Persistent=true` to catch
missed runs after downtime and send only completed periods. Daily checks retry
pending mail after a transport failure. Align the host timezone and
`MIKROTIK_REPORT_TIMEZONE` if the first check should occur soon after a period
closes. `MIKROTIK_MONTHLY_SUBJECT` optionally sets the monthly email subject;
the recipient and mail account are shared with the weekly report.

For a manual run, use the same environment and user as the service:

```bash
sudo systemctl start mikrotik-report-collect.service
sudo systemctl start mikrotik-report-weekly.service
sudo systemctl start mikrotik-report-monthly.service
sudo journalctl -u mikrotik-report-collect.service -u mikrotik-report-weekly.service -u mikrotik-report-monthly.service -n 100
```

To test the complete path before the week closes, run a transient service with
the same user and environment as the weekly service. Do this after at
least one successful collection:

```bash
sudo systemd-run --wait --collect --pipe \
  -p User=YOUR_USER \
  -p Group=YOUR_USER \
  -p WorkingDirectory=/path/to/mikrotik-report \
  -p EnvironmentFile=/path/to/mikrotik-report/.env \
  /usr/bin/python3 /path/to/mikrotik-report/mikrotik_report.py test-report
```

`test-report` fetches a live RouterOS sample, reads the SQLite database in
read-only mode, calculates a preview of the current incomplete week in memory,
and sends it through the configured mail helper to `MIKROTIK_REPORT_TO` with a
`[TEST]` subject and a clear test banner. It does not update counters, close a
week, or remove pending reports. Success prints `Sent test report`; a RouterOS
or mail failure exits nonzero. The preview may include the latest observed
counter delta, which the next scheduled collection will still record normally.

To inspect an arbitrary historical interval, run `range` as a user that can read
the configured database:

```bash
cd /path/to/mikrotik-report
MIKROTIK_REPORT_DB=/var/lib/mikrotik-report/report.sqlite3 \
MIKROTIK_REPORT_TIMEZONE=Etc/UTC \
  python3 mikrotik_report.py range --from 2026-09-16 --to 2026-10-03
```

`--from` is inclusive and `--to` is exclusive. Both are local-calendar dates in
`MIKROTIK_REPORT_TIMEZONE`, so the example covers September 16 at 00:00 through
October 3 at 00:00 in that timezone. The command reads persisted daily
aggregates and writes only to stdout; it does not contact RouterOS, modify the
database, or send mail. Consequently, only `MIKROTIK_REPORT_DB` and optionally
`MIKROTIK_REPORT_TIMEZONE` are needed when invoking it outside the full service
environment.

Range totals include samples persisted inside the requested dates, including
ranges that cross weekly or monthly boundaries. Address-list maxima cover all
sampled days and the latest size comes from the last sampled day. The detected
destination-port and recurring-source tops use the same exact date boundaries.
The quality block compares observed samples with the nominal five-minute cadence
over the exact interval. Partial coverage is marked explicitly and totals then
describe only observed samples; a range with no persisted samples reports
activity as unavailable rather than zero. Data from before daily aggregate
collection was introduced cannot be reconstructed from current RouterOS
counters.

The first collection establishes a baseline; it does not claim traffic that
occurred before installation. Each later sample adds the difference from the
previous value. A lower counter or a detected router reboot starts a new
counter sequence. A newly observed rule starts with a fresh baseline to avoid
counting traffic that may have occurred before the collector saw it. If a rule
disappears, its last baseline is discarded. The report includes observed
router reboots, other counter resets, and new or recreated rule baselines.

Weekly boundaries use `MIKROTIK_REPORT_TIMEZONE`: Monday 00:00 is inclusive and
the following Monday 00:00 is exclusive. Monthly boundaries use day 1 at 00:00
inclusive through day 1 of the next month at 00:00 exclusive, in the same
timezone. Each counter difference is credited to the local day, week, and month
in which its later sample occurs. Monthly totals sum daily aggregates, so a
week crossing a month boundary is split correctly. Polling gaps, rules
created and removed between samples, and a reset followed by a counter that
already exceeds the old value without a detectable reboot can undercount or
hide a reset. They cannot be reconstructed from periodic counters. The report's
data-quality block shows observed samples, approximately expected samples and
coverage, router reboots, counter resets, and rule rebaselines. Expected samples
use a nominal five-minute cadence and the actual duration of the calendar period
in the configured timezone, including daylight-saving changes. Collection is
not fixed to an exact wall-clock grid, so the percentage is an estimate and can
slightly exceed 100% after manual collections. A week with no samples is not
evidence of zero blocked traffic.

The weekly email compares local and CrowdSec packet and byte totals, and the
latest and observed maximum size of each address list, with the immediately
preceding calendar week. Each comparison shows current and previous values,
absolute and percentage changes, and direction. Percentage change is unavailable
when the previous value is zero. A compact four-week trend lists traffic totals,
latest list sizes, and coverage, with missing weeks shown explicitly. Both weeks
must have at least 90% of the nominal sample count for a comparison; lower
coverage is shown as unavailable rather than as zero. The trend applies the same
rule. Router reboot, counter reset, and rule rebaseline counts are informational,
not traffic metrics. A separate compact top lists up to ten destination
`port/protocol` pairs by local detection-event count. These counts are neither
packet volume nor unique attacks. A second top lists up to ten source IPs by
recurring local detection-event count; it does not represent unique attacks or
confirm that a source was malicious. When persisted ASN metadata is available,
the source-IP top includes the ASN and organization; report generation never
performs a network lookup. A separate ASN top groups those detection events by
persisted ASN and shows detection count, distinct source-IP count, share of all
source-detection events, and resolved-metadata coverage. Unresolved IPs remain
in the source-IP top and in the ASN share denominator. ASN shares do not
represent firewall packet or byte shares. With enrichment disabled, reports
remain available and state explicitly when recorded IPs have no ASN metadata.
Historical comparisons start becoming
available after the first completed week has been emailed with sufficient
coverage. Earlier reports are not reconstructed from current router counters.

The monthly email shows local and CrowdSec packet and byte totals, latest and
maximum observed address-list sizes, and the same data-quality fields as the
weekly email. It also aggregates the destination-port top over the exact
calendar month and includes the recurring-source top for the same boundaries.
Month-over-month comparisons use the same current, previous, absolute change,
percentage, and direction rules. Both months need at least 90% estimated sample
coverage; a missing or low-coverage previous month is shown as unavailable. An
entirely unsampled month has unavailable activity values, not zero traffic. The
first month after upgrading may have low coverage because earlier collections
did not create daily aggregates. The monthly command queues each completed
month since the first daily aggregate, including months with no samples, and
records successful delivery so a later daily timer run does not resend it.

SQLite transactions serialize collection and reporting, and state survives
host restarts. A completed week or month stays pending if email delivery fails;
the corresponding report command exits nonzero and the next timer run retries.
A weekly aggregate enters the bounded history only after successful delivery.
If the process crashes after the mailer accepts a message but before SQLite
records success, the next run can send that period again. No additional SMTP
mechanism is used.

To recover, fix the router connection or mail configuration and restart the
failed service. Back up the SQLite file with SQLite's backup API or while all
timers are stopped; do not copy it during a write. To reset all reporting
history, stop all timers, move the database aside, and start them again. The
next collection will establish a new baseline.

## Code organization

`mikrotik_report.py` is a compatibility entry point kept stable for the systemd
units. The implementation lives in the `mikrotik_reporting` package:

* `config.py` validates command-specific environment configuration;
* `routeros.py` reads and validates RouterOS REST responses and normalizes
  lightweight detection log entries;
* `asn.py` performs optional bounded bulk ASN lookups for new source IPs;
* `models.py` and `aggregation.py` define report data, calendar windows,
  counter deltas, and coverage;
* `storage.py` owns the SQLite schema, migrations, counter aggregates, bounded
  detection cursor, daily destination-port counts, daily source-IP detection
  counts, normalized ASN metadata, and ASN detection summaries;
* `rendering.py` produces report text without external side effects;
* `workflows.py` coordinates transactions, collection, and direct invocation of
  the configured external mail transport;
* `scheduler.py` runs those workflows sequentially on explicit intervals and
  handles foreground-process termination;
* `cli.py` maps the six commands (`collect`, `report`, `report-monthly`,
  `test-report`, `range`, and `run`) to those workflows.

Keep business decisions out of the CLI and SQLite helpers. New report formats
should consume aggregates through `rendering.py`; new collection data should be
normalized by `routeros.py` before it reaches aggregation or persistence.

## Local validation

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q mikrotik_report.py mikrotik_reporting
./verify-systemd-units.sh
./verify-compose.sh
./verify-container.sh
python3 -m pip install -r requirements-check.txt
python3 -m ruff check .
python3 -m ruff format --check .
python3 -m pyright
```

The tests use synthetic RouterOS responses and temporary SQLite files. They
do not contact the router or send email. This repository change does not enable
RouterOS `www-ssl`, create an account, or install systemd units on a live host.

RouterOS REST behavior and rule counters are documented by [MikroTik REST API](https://manual.mikrotik.com/docs/developer-guides/rest-api/)
and [MikroTik firewall matchers](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/common-firewall-matchers-and-actions/).
The dedicated memory buffer follows [MikroTik logging](https://manual.mikrotik.com/docs/system/logging/).
The user group policies and address restriction are documented by [MikroTik User](https://manual.mikrotik.com/docs/authentication-authorization-accounting/user/).
ASN lookup behavior and field semantics follow [Team Cymru IP to ASN Mapping](https://www.team-cymru.com/ip-asn-mapping/);
the returned registry country is not used as geolocation.
