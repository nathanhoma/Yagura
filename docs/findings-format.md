# Findings format (schema version 1)

The persisted file and JSON export use one document:

```json
{
  "schemaVersion": 1,
  "findings": [],
  "evidence": []
}
```

Every finding has an opaque `id`, a `kind` (`host`, `service`, or `observation`), a `title`, a `detail`, an array of `evidenceIds`, ISO UTC timestamps (`firstSeen`, `lastSeen`, `createdAt`, `updatedAt`), and `reviewStatus` (`unreviewed` or `reviewed`). `firstSeen` and `lastSeen` describe observation time; creation and update timestamps describe storage time.

| Kind | Fields | Relationships / identity |
| --- | --- | --- |
| host | `ip`, `aliases`, `name`, `state`, `local`; optionally `mac`, `interface`, `prefix`, `neighborState` | Identity is a numeric IPv4 or IPv6 address, including aliases retained by an explicit merge. Local interface addresses have `local: true`. |
| service | `port`, `protocol`, `state`, `name`, `product`, `version`, `tunnel` | `hostId` references a host. Identity is host + port + protocol. Protocol is tcp, udp, or sctp; port is 1–65535. |
| observation | `title`, `detail` | `hostId` and `serviceId` are nullable. When a service is linked, its host is also linked. Exact observations deduplicate by linked host/service + title + detail. |

Evidence has `id`, `tool`, `command`, `output`, `format`, `observedAt`, and `importedAt`, plus a `sensitive` flag for general imports. An import accepts up to 800 KB, but sensitive evidence is stored as a redacted marker; recognized credential values in other imports are masked. API reads, analysis, and JSON/CSV export use the same sanitized view. Source commands are metadata; the importer never executes them. Manual notes create evidence with `tool: "manual"`. Existing raw files are sanitized when next saved, so review older workspaces before sharing their files directly.

Imports merge identities and add evidence references. Observation time controls `firstSeen`/`lastSeen`; older results do not overwrite newer parsed fields. Reviewed records retain their corrected fields on later imports. Host merges preserve the absorbed host address as an alias, repoint all child links, and combine matching services. Service merges require the same host, port, and protocol. Merging observations keeps the survivor's title and links, combines distinct details, and unions evidence. Deleting a host removes its linked services and observations; deleting a service removes its linked observations. Evidence remains in the JSON export.

Legacy arrays are migrated on first read, with the original file preserved as `data/findings.json.legacy.bak`. IDs remain stable after migration. Writes use an atomic file replacement. A malformed or unsupported stored file fails explicitly rather than being overwritten with an empty workspace.

The CSV export contains sanitized finding fields, relationship IDs, evidence IDs, and source commands. The JSON export contains the sanitized graph and evidence; sensitive evidence bodies are replaced with markers. Imported IPv6 and public addresses can be reviewed and exported, but next commands are generated only for approved, non-interface private/local IPv4 targets.
