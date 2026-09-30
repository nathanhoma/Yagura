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

The workspace is split into Recon, Findings, Analysis, and Next checks views. The target map shows recon, service identification, and access triage stages. Built-in rules propose checks for known targets: ICMP reachability, common TCP ports, version probes for recorded open ports, web headers, and SMB shares. Commands have concrete target/port values and links to their supporting findings and evidence. The full command catalog remains available even without a model. Each concrete suggestion has a Run button. Confirm authorization in the Next checks view before running one; the server checks the current stored candidate and runs fixed arguments without a shell. Ping and Nmap output is imported when parseable. Other check output appears in the result dialog.

Optional local LLM configuration uses an OpenAI-compatible endpoint:

```env
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=
LLM_API_KEY=
```

Copy `.env.example` to `.env` and set the endpoint. The Analysis view lists models advertised by that endpoint; the selected model is used for analysis and suggestions. `LLM_MODEL` remains an optional server default. Only localhost or literal private/local IP endpoints are accepted; redirects are refused. Command ranking receives stored finding summaries, eligible checks, and the fixed command catalog. Findings analysis also receives bounded excerpts from linked raw evidence. It selects candidate IDs, while the server supplies verified commands, reasons, and evidence links. If `LLM_MODEL` is empty and `/models` advertises exactly one model, the service selects it automatically; with multiple models, choose one in the UI. Invented commands or unsupported targets cannot pass through. Built-in checks remain available if the model is missing, unreachable, or returns invalid results.

## Local discovery scope

- **Read local network state** runs `ip -j -4 addr` and `ip -j -4 neigh` and saves results as linked findings/evidence.
- Nmap discovery runs `nmap -n -sn -oX - <CIDR>` after authorization is checked. Only RFC1918, loopback, or link-local IPv4 CIDRs with up to 1,024 addresses (`/22` through `/32`) are accepted.
- Passive imports may contain other addresses. Automated suggestion generation is limited to recorded non-interface private/local IPv4 targets.
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
| `POST /api/checks/run` | Run a current suggested check by `candidateId` with `authorized:true`; arbitrary command strings are ignored. |

Responses contain `status`, `source`, `model`, `scope`, `counts`, `summary`, `assessments`, `suggestions`, `snapshotId`, `generatedAt`, `stale`, and `warnings`. Assessments have `findingIds`, `evidenceIds`, `interpretation`, and `uncertainties`. References must point to evidence supplied to the model and linked to each cited finding. Suggestions resolve only to server-generated eligible commands. Citation validation checks references, not the factual correctness of model prose.

Analysis uses a bounded context (up to 100 findings, 40 evidence excerpts, and about 24,000 characters) without modifying raw evidence. Output errors, connection failures, timeout, and authentication errors return `status: "fallback"`, `source: "built-in"`, and an explicit error code. Concurrent requests for the same snapshot share the in-flight model request. `LLM_TIMEOUT_MS` defaults to 30,000 and is capped at 60,000.

### Live LLM smoke test

```sh
npm run test:llm
```

This legacy Node script checks the former backend. The Python backend is covered by the tests above; a live Python model check can be made from the Analysis view. The script runs only a three-request ping against **10.0.4.80** and writes a report to `/tmp/yagura-llm-live-test.json`.
