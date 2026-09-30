# Yagura

Yagura is a local recon and initial-access triage workspace. Import command results, review linked hosts/services/observations, inspect original evidence, and choose the next check from recorded findings. The backend runs on Python 3.10+ using only the standard library; the browser UI remains HTML and JavaScript.

## Run

```sh
python3 main.py
```

Open <http://127.0.0.1:8080>. On Kali, install `iproute2` and optionally `nmap` to use local discovery. Findings are stored in `data/findings.json`. The server binds to localhost by default.

## Import and review

1. Select `nmap`, `ip addr`, `ip neigh`, or `ping` in **Import command output**.
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

XML preserves separate Nmap product and version fields. Normal text retains the full version description in `product`, because the text format does not consistently separate its components. Unrecognized or incomplete outputs return an error. A no-reply ping records `no-response`, which does not establish that a host is down. Re-imports deduplicate linked records while adding evidence; reviewed corrections survive later imports. Existing flat notes migrate automatically with a backup of the original file.

See [the common findings format](docs/findings-format.md) for fields, identity rules, timestamps, and merge behavior.

## Workflow and suggestions

The workspace is split into Recon, Findings, Analysis, and Next checks views. The target map shows recon, service identification, and access triage stages. Enter an authorized IPv4 CIDR in Next checks before any concrete command is proposed; leaving it empty produces no target commands. Use a `/32` for one host. Built-in rules then propose checks only for recorded hosts inside that range: ICMP reachability, common TCP ports, version probes, OS fingerprinting for recorded open TCP services, web headers, and SMB shares. TCP port discovery and service version checks explicitly use Nmap TCP connect mode (`-sT`) for networks where SYN scans are filtered. OS detection uses `nmap -n -Pn -O` and may require elevated privileges. Commands have concrete target/port values and links to their supporting findings and evidence. The full command catalog remains available as reference templates. Each concrete suggestion has a Run button. Confirm authorization in the Next checks view before running one; the server checks that the current stored candidate is inside the supplied CIDR and runs fixed arguments without a shell. Ping and Nmap output is imported when parseable. Other check output appears in the result dialog.

Optional local LLM configuration uses an OpenAI-compatible endpoint:

```env
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=
LLM_API_KEY=
```

Copy `.env.example` to `.env` and set the endpoint. The Analysis view lists models advertised by that endpoint; the selected model is used for analysis and suggestions. `LLM_MODEL` remains an optional server default. Only localhost or literal private/local IP endpoints are accepted; redirects are refused. Command ranking receives stored finding summaries, eligible checks, and the fixed command catalog. Findings analysis also receives bounded excerpts from linked raw evidence. It selects candidate IDs, while the server supplies verified commands, reasons, and evidence links. If `LLM_MODEL` is empty and `/models` advertises exactly one model, the service selects it automatically; with multiple models, choose one in the UI. Invented commands or unsupported targets cannot pass through. Built-in checks remain available if the model is missing, unreachable, or returns invalid results.

## Published website contacts

For a recorded open HTTP(S) service inside the authorized check range, **Next checks** can suggest **Inspect published website contacts**. Set the host record's **Hostname** to the exercise site's actual name (for example `www.exercise.test`) when it uses virtual hosting. The command keeps that name for HTTP Host and TLS SNI but pins the connection to the recorded, scoped IP. HTTPS certificate verification remains enabled.

The executable command is `python3 -m backend.web_contacts --url <website-url> --ip <recorded-ip>`. The app constructs its arguments from the stored host and service; it does not accept arbitrary URLs or commands in the execution request. The standalone command also restricts its connection IP to private/local IPv4 addresses, matching the app's current scope.

The check reads page text and `mailto:` recipients, deduplicates addresses, and follows up to five same-origin pages (contact/about links first). Other origins, ports, URL credentials, and external redirects are rejected; no JavaScript or forms are executed. Limits are 256 KB per page, 25 distinct addresses, and a bounded request duration. The report and source URLs are saved as linked findings/evidence. Zero, one, or multiple addresses refer only to inspected pages; this does not prove whole-site uniqueness. Fetch errors and incomplete coverage remain visible in the evidence.

## Email drafts

Open **Email drafts** to select a discovered contact or enter a recipient manually. The sender address and name are optional so you can prepare messages before exercise infrastructure is confirmed. Edit the subject and plain-text body, save and reopen drafts, preview them, or copy their text. **Export .eml** saves the current draft and downloads a MIME message with `X-Unsent: 1`; unknown sender details are omitted. Internal notes and source evidence are excluded from exported messages.

**Suggest wording** uses the drafting brief and optional existing subject/body with your configured local model. It previews the suggestion and applies it only after **Use this wording**. Generation does not save the draft, send email, or configure sender infrastructure. Manual editing works without a model. This release has no SMTP transport or email delivery endpoint.

Drafts are stored separately in `data/email-drafts.json` with recipient source references derived from saved contact findings. Conflicting edits from another browser tab are rejected rather than overwriting newer content. Drafts are not part of the findings JSON/CSV export; use `.eml` export for messages. The API provides `GET/POST /api/email-drafts`, `PATCH/DELETE /api/email-drafts/{id}`, `GET /api/email-drafts/{id}/export`, `GET /api/email-contacts`, and `POST /api/email-drafts/generate`.

## Local discovery scope

- **Read local network state** runs `ip -j -4 addr` and `ip -j -4 neigh` and saves results as linked findings/evidence.
- Nmap discovery runs `nmap -n -sn -oX - <CIDR>` after authorization is checked. Only RFC1918, loopback, or link-local IPv4 CIDRs with up to 1,024 addresses (`/22` through `/32`) are accepted.
- Passive imports may contain other addresses. Automated suggestion generation requires an explicitly supplied authorized CIDR and is limited to recorded non-interface private/local IPv4 targets inside it. A private address or neighbor entry alone does not establish authorization.
- Keep the app bound to localhost unless you add access controls. Public asset serving excludes configuration, source modules, and the data directory.

## Validate

```sh
python3 -m unittest discover -s test -p 'test_*.py'
```

Python tests cover the parser, record merging, API persistence, scope limits, and analysis fallback. No real scans or model are required. The former Node implementation and its tests remain in the repository for reference; `npm start` and `npm test` now run the Python app and tests.

## Findings analysis backend

Use **Findings analysis** in the UI to analyze all recorded findings or one host. **Test model connection** checks the endpoint and model list. Each interpretation links to the supplied findings and evidence and is labeled as a model hypothesis requiring review. Missing services, authentication evidence, and other uncertainties are returned separately. The latest analysis is saved locally in `data/analysis.json`; edits/imports mark it stale. The analysis service never runs target commands.

| API | Purpose |
| --- | --- |
| `GET /api/llm/health` | Check model discovery, authentication, endpoint reachability, and model selection. Credentials are never returned. |
| `POST /api/analysis` | Analyze persisted findings; body `{}` selects all or `{"hostId":"stored-host-id","model":"advertised-model"}` selects a host and model. Client-supplied findings/commands are rejected. |
| `GET /api/analysis/latest` | Return the saved analysis and current `stale` flag, or `{"analysis":null}`. |
| `POST /api/checks/run` | Run a current suggested check by `candidateId` with `authorized:true` and `authorizedCidr`; arbitrary command strings are ignored. |

Responses contain `status`, `source`, `model`, `scope`, `counts`, `summary`, `assessments`, `suggestions`, `snapshotId`, `generatedAt`, `stale`, and `warnings`. Assessments have `findingIds`, `evidenceIds`, `interpretation`, and `uncertainties`. References must point to evidence supplied to the model and linked to each cited finding. Suggestions resolve only to server-generated eligible commands. Citation validation checks references, not the factual correctness of model prose.

Analysis uses a bounded context (up to 100 findings, 40 evidence excerpts, and about 24,000 characters) without modifying raw evidence. Output errors, connection failures, timeout, and authentication errors return `status: "fallback"`, `source: "built-in"`, and an explicit error code. Concurrent requests for the same snapshot share the in-flight model request. `LLM_TIMEOUT_MS` defaults to 30,000 and is capped at 60,000.

### Live LLM smoke test

```sh
npm run test:llm
```

This legacy Node script checks the former backend. The Python backend is covered by the tests above; a live Python model check can be made from the Analysis view. The script runs only a three-request ping against **10.0.4.80** and writes a report to `/tmp/yagura-llm-live-test.json`.
