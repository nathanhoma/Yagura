# Yagura

Yagura is a local recon and initial-access triage workspace. Import command results, review linked hosts/services/observations, inspect original evidence, and choose the next check from recorded findings. The backend runs on Python 3.10+ using only the standard library; the browser UI remains HTML and JavaScript.

## Run

```sh
python3 main.py
```

Open <http://127.0.0.1:8080>. On Kali, install `iproute2` and optionally `nmap` to use local discovery. Findings are stored in `data/findings.json`. The server binds to localhost by default.

If **Read local network state** reports that the API is unavailable or `Not found.`, check the address in the browser. This button sends `POST /api/discovery/local` to the same host and port that served the page. Start this project's Python server with `python3 main.py` and open its printed address. A static preview server or an older copy of Yagura may serve the page but lack that API route. For access from another machine, configure `APP_HOST` and `APP_PORT` on the machine running Yagura; the local network state shown is that server machine's state.

## Import and review

1. Select `nmap`, `ip addr`, `ip neigh`, `ping`, `httpx`, or `nuclei` in **Import command output**.
2. Paste the complete output or select a file up to 800 KB. Supply the source command and optionally the observation timestamp (entered in your browser's local time).
3. Preview the parsed records, then save the import. Inspect and correct records using **Edit**; saving marks them reviewed.
4. Use the target/service map and evidence links to inspect each relationship and original command output. **Merge** combines duplicates, preserves evidence, and redirects child links.
5. Export the complete graph and evidence as JSON, or finding rows with source commands as CSV.

| Parser | Supported output |
| --- | --- |
| nmap | Standard XML (`-oX`), or normal console / `.nmap` text; host states, port states, services, version details, script observations |
| ip addr | `ip -j addr` JSON or normal `ip addr` text, including IPv4/IPv6 interface addresses |
| ip neigh | `ip -j neigh` JSON or normal `ip neigh` text, including MAC/interface/neighbor state; `[]` represents an empty table |
| ping | Linux/iputils text and Windows text with a numeric target address; reply statistics and reachability observations |
| httpx | ProjectDiscovery JSONL with a numeric target IP; HTTP status, title, and technologies become linked observations |
| nuclei | ProjectDiscovery JSONL with a numeric target IP; template ID, name, and severity become linked observations requiring review |

XML preserves separate Nmap product and version fields. Normal text retains the full version description in `product`, because the text format does not consistently separate its components. Unrecognized or incomplete outputs return an error. A no-reply ping records `no-response`, which does not establish that a host is down. Re-imports deduplicate linked records while adding evidence; reviewed corrections survive later imports. Existing flat notes migrate automatically with a backup of the original file.

See [the common findings format](docs/findings-format.md) for fields, identity rules, timestamps, and merge behavior.

## Workflow and suggestions

The workspace is split into Scope → Actions → Findings → Analysis. Actions contains Next checks and Email drafts. The target map shows recon, service identification, and access triage stages. Confirm and save up to 16 authorized IPv4 CIDRs and optional domain suffixes in Scope. Each CIDR may contain up to 1,024 addresses, with up to 4,096 addresses total. RFC1918 and shared `100.64.0.0/10` ranges are supported, along with loopback and link-local ranges for local testing. The scope is saved in `data/scope.json`; an old single-`cidr` file is read automatically. Saving does not run discovery. Each scan or executable check requires separate confirmation.

Discovery accepts any subnet contained in the saved CIDRs, even when domains are set, but runs at a low global Nmap rate and saves newly seen IPs only in `data/discovery.json` as **unverified**. Discovery does not create executable findings. In Scope, enter one to four explicit internal resolver IPs that are also in the saved CIDRs, review PTR and A answers with resolver IP, time and TTL, then explicitly approve one forward-confirmed name/IP pair. Split resolver answers require a review reason. Only then is the host promoted into findings. In a domain-bound scope, older imported hosts also require this approval before executable suggestions or analysis; edits to an approved IP or name invalidate eligibility. Checks revalidate the current scope and approval on the server.

Built-in checks include ICMP reachability, common TCP ports, version probes, OS fingerprinting, web headers and inventory, SMB shares, and selected SSH/SMB/NFS scripts. TCP discovery and version checks use Nmap TCP connect mode (`-sT`); OS detection may require elevated privileges. Commands carry target and port values and link to evidence. They run without a shell, and parseable output is saved as linked findings. `httpx` and Nuclei JSONL can still be imported for review. Executable Nuclei and system-resolver PTR suggestions are disabled; DNS review instead uses only explicitly selected internal resolvers.

The web inventory check pins each connection to the approved IP while preserving the configured hostname for virtual hosting. It reads up to five same-origin pages and one randomized not-found baseline; it records 200/401/403/redirect responses, title, server header, bounded form metadata, up to 50 linked routes, and baseline similarity. Cross-origin redirects and forms are recorded but never followed or submitted. Query values and form values are not retained. The Findings view has a per-host Web survey of saved reports. No JavaScript is executed.

In **Next checks**, **Edit & run** opens the suggested command for review. The server accepts bounded changes to ping count (1–5), Nmap top-port count (1–1,000), recorded service ports or version level, and HTTP header timeout (1–20 seconds) or same-origin path. Other commands can be rerun unchanged. The program, target, and required options cannot be changed in this editor. The edited command is checked against the current candidate and saved scope, executed without a shell, and recorded as the evidence source command. The same authorization checkbox is required for Run and Edit & run.

**Short automatic check run** in Next checks lets you select one approved host and preview up to three exact commands before starting. It uses a limited set of reachability, TCP port/service, HTTP header, and SSH host-key checks. The browser runs the listed commands in order through the existing checked execution API; it never adds newly suggested commands mid-run. Before each command, it compares the saved scope and current candidate with the preview. It stops on no ICMP reply, a failed check, an import warning or missing import, a changed scope or candidate, or a stop request. Stop takes effect after any check already in progress. Each result and the stopping reason remain visible in the page until another preview is made. Closing the page ends the sequence after any in-flight check; there is no background job.

A ping with complete statistics but zero replies is shown as **No response**, not **Failed**. Its observation is still saved, and an automatic run stops before the next check; no ICMP reply does not prove the host is down. Tool errors and results that cannot be imported remain **Failed**.

The reference catalog still describes ffuf and Nuclei, but neither is executable through Yagura until an independently tested, host-level egress boundary is installed. The application-level pinning and approval checks are not a substitute for a host firewall or isolated network namespace, especially for third-party tools or a browser. Do not run ZAP or a browser-based crawler on kaliai05 before that boundary is verified.

Optional local LLM configuration uses an OpenAI-compatible endpoint:

```env
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=
LLM_API_KEY=
```

Copy `.env.example` to `.env` and set the endpoint. The Analysis view lists models advertised by that endpoint; the selected model is used for analysis and suggestions. `LLM_MODEL` remains an optional server default. By default, only localhost or literal private/local IP endpoints are accepted; redirects are refused. Command ranking receives stored finding summaries, eligible checks, and the fixed command catalog. Findings analysis also receives bounded excerpts from linked raw evidence. It selects candidate IDs, while the server supplies verified commands, reasons, and evidence links. If `LLM_MODEL` is empty and `/models` advertises exactly one model, the service selects it automatically; with multiple models, choose one in the UI. Invented commands or unsupported targets cannot pass through. Built-in checks remain available if the model is missing, unreachable, or returns invalid results.

For an explicitly trusted gateway DNS name, set `LLM_BASE_URL` to its HTTPS `/v1` URL and `LLM_TRUSTED_HTTPS_HOST` to that exact hostname. HTTP, other DNS names, credentials in the URL, query strings, fragments, and redirects remain blocked; HTTPS certificate verification remains enabled. Only sanitized, bounded evidence excerpts are sent to the configured gateway during analysis; explicitly marked sensitive evidence bodies are excluded. Keep `LLM_API_KEY` in the untracked `.env` file with owner-only permissions.

## Published website contacts

For a recorded open HTTP(S) service inside the authorized check range, **Next checks** can suggest **Inspect published website contacts**. Set the host record's **Hostname** to the exercise site's actual name (for example `www.exercise.test`) when it uses virtual hosting. The command keeps that name for HTTP Host and TLS SNI but pins the connection to the recorded, scoped IP. HTTPS certificate verification remains enabled.

The executable command is `python3 -m backend.web_contacts --url <website-url> --ip <recorded-ip>`. The app constructs its arguments from the stored host and service; it does not accept arbitrary URLs or commands in the execution request. The standalone command accepts only private, shared, or local IPv4 addresses. The app additionally enforces the saved CIDRs and domains before invoking it.

The check reads page text and `mailto:` recipients, deduplicates addresses, and follows up to five same-origin pages (contact/about links first). Other origins, ports, URL credentials, and external redirects are rejected; no JavaScript or forms are executed. Limits are 256 KB per page, 25 distinct addresses, and a bounded request duration. The report and source URLs are saved as linked findings/evidence. Zero, one, or multiple addresses refer only to inspected pages; this does not prove whole-site uniqueness. Fetch errors and incomplete coverage remain visible in the evidence.

## Email drafts

Open **Email drafts** to select a discovered contact or enter a recipient manually. The sender address and name are optional so you can prepare messages before exercise infrastructure is confirmed. Edit the subject and plain-text body, save and reopen drafts, preview them, or copy their text. **Export .eml** saves the current draft and downloads a MIME message with `X-Unsent: 1`; unknown sender details are omitted. Internal notes and source evidence are excluded from exported messages.

**Suggest wording** uses the drafting brief and optional existing subject/body with your configured local model. It previews the suggestion and applies it only after **Use this wording**. Generation does not save the draft, send email, or configure sender infrastructure. Manual editing works without a model. This release has no SMTP transport or email delivery endpoint.

Drafts are stored separately in `data/email-drafts.json` with recipient source references derived from saved contact findings. Conflicting edits from another browser tab are rejected rather than overwriting newer content. Drafts are not part of the findings JSON/CSV export; use `.eml` export for messages. The API provides `GET/POST /api/email-drafts`, `PATCH/DELETE /api/email-drafts/{id}`, `GET /api/email-drafts/{id}/export`, `GET /api/email-contacts`, and `POST /api/email-drafts/generate`.

## Target scope and server diagnostics

- Optional **Yagura server network** diagnostics run `ip -j -4 addr` and `ip -j -4 neigh` and save results as linked findings/evidence for server context without changing the target scope.
- Nmap discovery runs with `-n -sn --max-rate 5 --max-retries 1` after authorization is checked. The target must be contained in a saved CIDR. Results stay quarantined until DNS review and approval; discovery never changes the saved scope.
- Passive imports may contain other addresses. The saved-scope workflow proposes executable checks only for recorded non-interface hosts matching both its IP ranges and, when configured, domain suffixes. A private address or neighbor entry alone does not establish authorization.
- Keep the app bound to localhost unless you add access controls. Public asset serving excludes configuration, source modules, and the data directory.

## Validate

```sh
python3 -m unittest discover -s test -p 'test_*.py'
```

Python tests cover the parser, record merging, API persistence, scope limits, and analysis fallback. No real scans or model are required. The Python backend is the only server implementation. `npm start` and `npm test` are optional shortcuts for the Python commands above; Node.js is not required when running Python directly.

## Findings analysis backend

Use **Findings analysis** in the UI to analyze all recorded findings or one host. **Test model connection** checks the endpoint and model list. Each interpretation links to the supplied findings and evidence and is labeled as a model hypothesis requiring review. Missing services, authentication evidence, and other uncertainties are returned separately. The latest analysis is saved locally in `data/analysis.json`; edits/imports mark it stale. The analysis service never runs target commands.

| API | Purpose |
| --- | --- |
| `GET /api/llm/health` | Check model discovery, authentication, endpoint reachability, and model selection. Credentials are never returned. |
| `GET/PUT /api/scope` | Read or save `{"cidrs":["100.96.1.0/24","10.1.51.0/24"],"domains":["crimsonia.net"]}`. Empty lists clear it. Legacy `{"cidr":"192.168.1.0/24"}` writes are accepted and migrated. |
| `POST /api/analysis` | Analyze persisted findings; body `{}` selects all or `{"hostId":"stored-host-id","model":"advertised-model"}` selects a host and model. Client-supplied findings/commands are rejected. |
| `GET /api/analysis/latest` | Return the saved analysis and current `stale` flag, or `{"analysis":null}`. |
| `POST /api/checks/run` | Run a current suggested check by `candidateId` with `authorized:true` and the saved `authorizedScope` object; arbitrary command strings are ignored. |

Responses contain `status`, `source`, `model`, `scope`, `counts`, `summary`, `assessments`, `suggestions`, `snapshotId`, `generatedAt`, `stale`, and `warnings`. Assessments have `findingIds`, `evidenceIds`, `interpretation`, and `uncertainties`. References must point to evidence supplied to the model and linked to each cited finding. Suggestions resolve only to server-generated eligible commands. Citation validation checks references, not the factual correctness of model prose.

Analysis uses a bounded context (up to 60 findings, 12 deduplicated evidence excerpts, and 10,000 characters). Select one host, all approved hosts, or a related group of up to eight approved hosts; evidence selection reserves a first pass across hosts before filling remaining slots. Evidence is sanitized before model submission. Unsupported model items are rejected individually when other grounded items remain. Output errors, connection failures, timeout, and authentication errors return `status: "fallback"`, `source: "built-in"`, and an explicit error code. Concurrent requests for the same snapshot share the in-flight model request. `LLM_TIMEOUT_MS` defaults to 30,000 and is capped at 60,000.

For a live local model check, use **Test model connection** in the Analysis view.

## Evidence-driven path hypotheses

Findings analysis now asks the local model to infer possible paths from collected evidence,
including relationships across hosts when **All stored findings** is selected. No exercise-specific
paths are embedded in the analysis rules. Each hypothesis contains ordered, cited steps,
prerequisites, missing evidence, counterevidence, and proposed investigations with expected
results and their impact on the hypothesis. Step status is the model's assessment, not a
server-verified exploitation result. The server validates the shape and supplied references.
Hypotheses are saved with the existing analysis snapshot and become stale when findings change.
Reanalyze after importing new evidence; this version recomputes hypotheses rather than maintaining
a longitudinal hypothesis history. A model outage shows recorded facts and existing checks,
without synthesizing attack paths.

Use **General investigation evidence** in Import command output for transcripts, configuration
excerpts, authentication results, or other text without a dedicated parser. Supply an evidence
title, optional numeric host IP, source command and observation time. No source command is executed.
Mark an item sensitive to replace its body and linked detail with a redacted marker at save time.
Known key/value credentials, authorization headers, and private keys are also redacted on save,
API responses, AI context, and JSON/CSV export. Pattern matching cannot identify every secret;
review existing raw files and mark sensitive imports explicitly. Existing files are sanitized
when subsequently saved, not silently rewritten on startup.

Proposed investigations can describe checks beyond the executable catalog. They are displayed
for manual review and have no Run button. Executable suggestions still resolve to server-generated
candidates and use the existing scope and execution checks. Analysis context remains bounded;
truncation is reported, and long evidence excerpts include the beginning and end. Detailed evidence
selection, automatic collection for new investigation types, and hypothesis history remain future work.

## Investigation catalog additions

The reference catalog now includes bounded route discovery, exposed configuration and Git-source
review, backup comparison, single known-credential SSH verification, process and KeePass inspection,
Windows identity, JEA connection and command discovery, routine metadata and existing output,
PFX metadata, signature status, MySQL grants/file policy, web process ownership, document response
comparison, and read-only SQLite inspection. These are reference templates requiring manual
execution and General investigation evidence import. They do not encode an expected attack path.

A new executable **Inspect web metadata exposure** check uses the existing IP-pinned transport and
verified TLS to issue six fixed GET requests (Git HEAD, WEB-INF configuration, library listing,
docs, and a missing-page baseline). Responses and errors become evidence, without an automatic
vulnerability verdict. Web inventory also records form actions, methods, encoding and field names,
and query parameter names without submitting forms or retaining field values. Existing scope and
per-check authorization apply. No new third-party dependencies are installed by the application.
Credential guessing, memory dumping/recovery, password cracking, payload execution and signed-job
submission have not been added as executable checks in this increment.
