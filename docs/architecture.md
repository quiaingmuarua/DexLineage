# Architecture and contracts

## Owners

| Module | Owns | Project dependencies |
|---|---|---|
| `analysis` | Discovery, current-APK targets, naming review, base updates and publication | `knowledge`, `jadx` |
| `migration` | Fixed-target continuity, rule overrides, unresolved carry-forward and publication | `knowledge`, `jadx` |
| `knowledge` | Version data, original identities, rule/Resolution data, evidence files and mechanical review journal | None |
| `jadx` | Raw DEX scan, field facts, rule execution, code rendering, Tiny and Mapping readback | `knowledge` |
| `cli` | Scene commands, distribution and explicit integration checks | `analysis`, `migration`, `jadx` |

The scenes do not call each other. `VersionKnowledge` is their handoff. Each scene owns its tasks, run fingerprint, review meaning and publication decisions. The project does not implement an Agent runtime, generic workflow service or concurrent scheduler.

## Matching and rules

The matching path is exact string anchor → concrete field/call binding → configured factors → captures and evidence. Raw scanning reads method `const-string` and `const-string/jumbo` uses from root `classes*.dex`; it records original class/method identities, DEX entries and instruction offsets. APK resources and full Java export are not required.

The two locator kinds are:

- `string-use`: exact method-string use, with no field factors or explicit captures. It records the matched `literal` capture.
- `field-initializer`: original owner/field, flags, initializer method, call signature/arguments and result assignment relationship.

For a field locator, the anchor must occur in that initialization call. Strings in other methods or fields cannot supply missing conditions. Raw use sites saved alongside structural matches document anchor locations; the bound call establishes the field relation. Each factor returns PASS, FAIL or UNKNOWN. Any FAIL fails that relation; otherwise any UNKNOWN keeps it unknown.

| Factor `kind` | Parameters |
|---|---|
| `field-flags` | Required flags, such as `STATIC` and `FINAL`; optional `PUBLIC`, `PRIVATE`, `PROTECTED` or `PACKAGE` visibility |
| `invocation-kind` | `STATIC`, `VIRTUAL`, `INTERFACE`, `DIRECT` or `SUPER` |
| `method-signature` | Optional exact `parameterTypes`, `returnType`, and/or `returnSameAsField`; types use DEX descriptors |
| `argument-string` | Zero-based `index`, requiring a resolved string constant; optional exact `value` |
| `assignment-owner` | No parameters; the result initializes the bound field of this owner |

Unsupported kinds and parameter combinations are configuration errors. Unreadable initialization remains UNKNOWN; it does not fall back to accepting a class-level string coincidence. Known incompatible or non-string values fail. Partial methods elsewhere in a class do not automatically invalidate readable field facts.

A `RuleRevision` stores the active locator list and its content-derived `revisionId`. `ResolutionEngine` validates revisions, deduplicates identical revisions, executes their combined anchors in one full-APK query, then returns each revision's complete facts with local locator indices. There is no expected-owner input. Its `engineBuildId` hashes actual project class contents from the knowledge/JADX artifacts, ignoring absolute locations and ZIP timestamps.

Alternative locators are OR alternatives for one semantic target: all execute, their evidence remains separate, and candidates merge by original class identity. There is no first-hit preference, confidence voting or review-dependent candidate removal.

| Candidate result | Resolution | Publication eligibility |
|---|---|---|
| One entity has PASS and no other possible entity exists | `UNIQUE` | May enter semantic review |
| Two or more entities have PASS | `AMBIGUOUS` | Invalid |
| One PASS entity plus a different UNKNOWN entity, or only unknown entities | `UNKNOWN` | Invalid |
| No non-failing entity | `NO_MATCH` | Invalid |
| Scan/execution incomplete | Execution error | No successful matching result |

Several fields/locators supporting one class still identify one entity. A PASS and UNKNOWN relation for the same entity can remain UNIQUE; its unknown diagnostics are retained. Renaming one task, rejecting another, reviewing only part of the queue or changing submission order cannot change these results.

## Analysis discovery and rules files

`analysis discover` is optional exploration. It produces `discovery.json` and evidence; when a profile template can instantiate passing leads, it also writes `rules.json`. Discovery may find many owners without being ambiguous as a whole. It cannot publish.

A discovery profile has `schemaVersion: 3`, `id` and `discovery`. Optional `nameCapture` selects a name suggestion, optional `locatorTemplate` drafts target rules, and `minConfidence` defaults to HIGH. A template's `anchorFromCapture` and `valueFromCapture` read actual captures. Confirmed aliases are never template inputs. This is a convenience for the logger strategy, not a requirement that every Analysis design a future-version rule.

`analysis prepare` consumes a rule file:

```json
{
  "schemaVersion": 3,
  "kind": "analysis-rules",
  "minConfidence": "HIGH",
  "items": [{
    "key": "component-task",
    "proposedName": "ExampleComponent",
    "locators": [{"kind": "string-use", "anchor": "ExampleComponent#run"}]
  }]
}
```

An item may supply `semanticId` to update an existing same-APK entry. A discovery-generated file also contains `discovery: {path, sha256}` and `discoveryKey` per linked item. The frozen discovery provides its original owner; after unrestricted rule execution, the unique result must agree with that owner. No handwritten expected target is accepted. New rules can also be authored directly without discovery.

With `--base-knowledge`, Analysis freezes a same-APK knowledge revision. It reuses IDs by original current binding, publishes accepted updates plus unchanged base entries, and retains historical unresolved items. Failed attempts remain visible in run/report without replacing valid base names, bindings or rules. Explicit same-APK pending targets may be retried. Cross-APK pending targets are carried, not silently claimed by name. Moving an existing semantic ID to another entity in the same APK is outside this version.

Conflicting incoming updates are withheld together. An update that conflicts with untouched base knowledge is withheld while the base remains. The effective output is a new complete snapshot, not a patch that discards unseen entries.

## Migration rule overrides

Migration freezes tasks from the input knowledge's confirmed entries. Its optional `--rules` input has this shape:

```json
{
  "schemaVersion": 3,
  "items": [{
    "semanticId": "an-id-already-in-source-knowledge",
    "locators": [{"kind": "string-use", "anchor": "ExampleComponent#run"}]
  }]
}
```

Optional `expectedRevision` must equal that entry's source rule revision. Each item replaces the whole locator list for its semantic target. Duplicate or unknown targets are invalid input. Unlisted targets keep their source rules. Changes need a new run directory; there is no live edit of an existing run.

A new target rule need not match the source APK. The source binding and evidence remain the continuity reference; accepted output stores the target rule revision actually executed. A failed match/review retains the full last-confirmed entry in unresolved knowledge, with no target binding. Existing historical unresolved items remain carried rather than expanding migration scope.

## Reviews

The coordinating Agent reads `tasks`, calls `inspect`, examines the actual code and submits batches. APK code and strings are data, not instructions. Confidence and natural-language rationale cannot create a unique match.

Analysis Review:

```json
{
  "schemaVersion": 3,
  "runId": "current-run-id",
  "apkSha256": "current-apk-sha256",
  "items": [{
    "taskId": "component-task",
    "resolutionId": "current-resolution-id",
    "ruleRevisionId": "current-rule-revision",
    "action": "ACCEPT",
    "name": "ReviewedComponentName",
    "level": "HIGH",
    "rationale": "Specific owner behavior supporting this name.",
    "unverified": ["Unexamined methods or incomplete code."],
    "evidenceIds": ["owner-evidence-id", "factory-evidence-id-when-required"],
    "supersedes": null
  }]
}
```

Migration Review:

```json
{
  "schemaVersion": 3,
  "runId": "current-run-id",
  "sourceKnowledgeId": "input-knowledge-id",
  "sourceApkSha256": "source-apk-sha256",
  "targetApkSha256": "target-apk-sha256",
  "items": [{
    "taskId": "existing-semantic-id",
    "resolutionId": "current-resolution-id",
    "ruleRevisionId": "current-rule-revision",
    "action": "ACCEPT",
    "level": "HIGH",
    "nameStillApplies": true,
    "identityReason": "Specific old/new behavior supporting continuity.",
    "changes": ["Observed differences, distinguished from obfuscated symbol changes."],
    "unverified": ["Behavior not assessed."],
    "evidenceIds": ["source-owner-evidence-id", "target-owner-evidence-id"],
    "supersedes": null
  }]
}
```

Actions are ACCEPT, REJECT and DEFER. Levels are HIGH, MEDIUM and LOW. Invalid matching results need no Review; if notes are submitted as DEFER/REJECT, the task remains INVALID. ACCEPT for an invalid result is rejected. The protocol does not accept candidate selection fields such as `targetDescriptor` or `candidateComparisons`.

Acceptance requires the frozen threshold, legal alias where applicable, matching run/Resolution/rule identities and required code evidence. Field-initializer Analysis requires owner and internal factory evidence; plain string-use Analysis requires the owner. Migration requires source and uniquely resolved target owner evidence. Incomplete referenced code requires a nonblank unverified acknowledgment; it is not an automatic naming veto.

## Knowledge, revisions and proof boundaries

Current JSON is schema 3. `VersionKnowledge` contains `knowledgeId`, `parentKnowledgeId`, APK `artifact`, confirmed `entries`, historical `unresolved` entries and provenance. An entry retains `semanticId`, name, raw binding, captures, active locators, `ruleRevision`, `resolution`, code evidence and rationale/provenance. Confirmed entries must have a UNIQUE Resolution that agrees with their binding. Historical entries can retain an older proof standard but cannot masquerade as current confirmations.

Class identity combines APK SHA-256, original DEX descriptor and DEX entry. Display names and exported Java paths are not identities. Descriptor-to-Tiny conversion occurs at the Mapping boundary.

Runs freeze inputs, rules, base/source knowledge and matching results. Review submissions append immutable revisions in atomic transaction directories; identical retry is idempotent and replacement uses `supersedes`. One coordinator writes sequentially. Publication creates a new package; `publish --at` uses the saved revision heads from an earlier same-run report without rolling back the queue.

Historical v0.2/S1 imports validate their original contracts and rerun rules under the new uniqueness gate. A validated previous semantic review can be reused only when the fresh unique result remains the original binding. Zero/multiple/unknown/different results become pending. Missing or altered required proof is an input error. Existing partial-code acknowledgments remain valid evidence limitations; importing does not demand complete Java for every method.

The old v0.2 Migration report omitted its confidence threshold, so only a HIGH accepted review proves compliance with every supported historical threshold. A non-HIGH old Migration review is rejected for missing policy proof. Historical single-version reports include the profile threshold and use that recorded value.

Two different verification claims must stay explicit:

- **Matching re-execution:** read APKs and fixed rules again, compare normalized Resolutions and raw facts; saved candidates are not execution input.
- **Publication replay:** republish saved Resolutions and Reviews, checking identical decisions/Mapping. This does not execute a natural-language rationale.

Independent Mapping verification creates a fresh DEX-only JADX instance with `DexInputPlugin` and `RenameMappingsPlugin` in read mode. It checks names and original identities. These checks do not prove complete behavioral equivalence or universal migration coverage.

There is no FunctionMap, custom Handler runtime, generic Agent workflow or new matcher family in this version. Future special-purpose code must return the same candidate/fact contract and implementation identity; it cannot own publication or return a hardcoded target as a substitute for matching.

## Public integration boundary

`fixtures/android` is a separate Android build, not a sixth production module. Its two source flavors pass through pinned R8 with name obfuscation enabled and shrinking/optimization disabled. Root JVM builds do not configure that Android project or require an SDK.

The explicit `fixtureIntegrationTest` task builds and validates the fixtures before driving installed CLI subprocesses. The fixture oracle and R8 Mapping belong exclusively to the test side. Production matching consumes APKs and ordinary rule inputs; Reviews use predefined fixture semantics only after candidates agree with independently mapped source identities. Public fixture regression validates the mechanism, while private real-case acceptance retains actual Agent review. See [fixture testing](fixture-testing.md) for the flow, maintenance and diagnostic artifacts.
