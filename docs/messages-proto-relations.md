# One-hop Proto relation analysis

`messages.proto-relations` restores class roles reached through numbered fields of an already resolved Proto parent. It uses the existing Analysis workspace, review journal and publication rules. The parent is a CLASS support anchor; it is not a renamed entry and does not enter Tiny Mapping.

The supported target is a **singular message type** or the **element type of a repeated message field**. The matcher reads the generated Lite message metadata and its actual field/type relationships from DEX. A rule selects a field number and cardinality, not a Java declaration position, an obfuscated field name or an expected child descriptor. Scalar fields can appear in the catalogue but cannot become class rename targets through this rule.

This is a bounded Messages strategy and a one-hop relationship reader. It does not recover field names, enum names, complete `.proto` schemas or recursive message graphs. Unsupported or unreliable metadata remains UNKNOWN; an absent field or a known cardinality mismatch is NO_MATCH. An APK read/scan failure is an execution error. Multiple definite related classes remain AMBIGUOUS, and unresolved competing paths prevent UNIQUE.

The initial decoder accepts the observed proto3 layout, presence fields, supported primitive/string/open-enum scalars and singular/repeated message fields. It consumes the entire metadata string and object-array cursor before accepting any child relation. Proto2/edition flags, bytes/bytes-list, map, oneof, group and unsupported feature bits remain UNKNOWN; a usable prefix cannot hide an unsupported suffix. Format reference: [protobuf v25.3 RawMessageInfo](https://github.com/protocolbuffers/protobuf/blob/v25.3/java/core/src/main/java/com/google/protobuf/RawMessageInfo.java).

## Configure the fixed targets

Copy these public examples into an ignored local case directory and replace their fictional service/RPC inputs and field selectors with inspected facts:

- [Workspace configuration](../examples/proto-relations-workspace.json)
- [Two-level parent seed rules](../examples/proto-relations-seeds.json)
- [Relation profile](../examples/proto-relations-profile.json)

The method profile declares `targets`, each with `key`, positive integer `fieldNumber`, and `cardinality` equal to `singular` or `repeated`. It may also provide `corpusTargetId` and/or `proposedName`. Unknown properties, duplicate keys, duplicate corpus targets and unsupported cardinalities are input errors.

The profile's discovery strategy is `messages.proto-fields`, with empty parameters and a `parent` dependency. The method emits one `messages.proto-field-type` rule for **every declared target**, including targets with no discovered child. Drafts do not use a child `discoveryKey`. `prepare` executes the numbered-field rules again; discovery facts never become candidate input or publication authority. This keeps absent fields and unsupported relationships visible as ordinary invalid tasks.

The method uses two seed rounds. With the example above:

1. Resolve the RPC METHOD anchor.
2. Resolve the request Proto CLASS anchor using that prior snapshot.
3. Discover parent fields, prepare the fixed target rules, and produce the review packet.

Both seeds are ordinary executable rules. A different inspected parent rule can replace the example seed definitions; it must still fit the declared finite seed plan. The method does not search class names or copy a parent's old APK address.

For an independent slice, omit `baseKnowledge`: passing a complete knowledge package as base would intentionally carry all of its confirmed entries into the new publication. An anchor-only seed publication keeps this slice limited to the reviewed children.

## Use a manual corpus

The workspace configuration accepts an optional `corpus` path, resolved relative to the configuration file:

```json
{
  "schemaVersion": 4,
  "apk": "source.apk",
  "profile": "proto-relations-profile.json",
  "seedRules": "proto-relations-seeds.json",
  "corpus": "manual-corpus/corpus.json"
}
```

Import the corpus with the existing `analysis import-jadx` command, then select actual target IDs from `analysis targets`. In a profile row, replace the example `proposedName` with that target's `corpusTargetId`. The workspace checks that declared corpus targets exist and that the corpus belongs to the supplied APK before executing seeds. It freezes the corpus, original annotation project and APK digests, and passes the corpus only to the final target preparation.

The original manual class is checked **after matching**. It never restricts the matcher. A unique result that disagrees with the manual source remains invalid. Review packets use the manual spelling when neither a canonical existing name nor an explicit proposal is present; the reviewer still has to read the evidence and submit a judgment. Importing a name does not accept it.

The full corpus remains available as context in the run. `proto-catalog.json` reports the profile's selected targets separately; it does not claim that other manual classes were processed in this slice. Newly confirmed classes receive the normal source-APK/entity semantic IDs, which Migration subsequently retains.

## Run, review and publish

After the normal JVM build, use the installed CLI:

```powershell
$cli = '.\build\install\dexlineage\bin\dexlineage.bat'
& $cli analysis run --method messages.proto-relations --config .local\proto\proto-relations-workspace.json --work .local\proto\source-work
& $cli analysis status --work .local\proto\source-work
```

At `WAITING_REVIEW`, use the returned `runPath` and `packetPath`. Read the parent metadata, child code and dependency evidence. Copy `review-template.json` out of the immutable workspace, fill the action, confidence, semantic rationale and unverified scope, then submit it:

```powershell
& $cli analysis submit --run '<runPath>' --review .local\proto\source-review.json
& $cli analysis resume --work .local\proto\source-work
```

Selected invalid tasks need no artificial Review. A valid ACCEPT still requires a unique result and the existing evidence/conflict checks. `resume` freezes the journal revisions and publishes; repeated COMPLETE resumes return the same package.

The source publication includes `knowledge.json`, class-only `mapping.tiny`, `report.json`, code evidence, the raw typed catalogue, and a readable `proto-catalog.json`. Each configured row shows its selector, observed types and final matching/review state. An observed type is a fact for investigation, not a confirmed binding.

## Migrate the same knowledge

Give the source publication's **unchanged** `knowledge.json` to the existing Migration commands. For the two-level example, use three immutable runs: RPC anchor, parent Proto anchor, then child targets.

```powershell
$sourceKnowledge = '<source knowledgePath>'
& $cli migration prepare --knowledge $sourceKnowledge --source-apk .local\proto\source.apk --target-apk .local\proto\target.apk --run .local\proto\migration-1
& $cli migration publish --run .local\proto\migration-1 --out .local\proto\target-round-1
& $cli migration prepare --knowledge $sourceKnowledge --source-apk .local\proto\source.apk --target-apk .local\proto\target.apk --target-base .local\proto\target-round-1\knowledge.json --run .local\proto\migration-2
& $cli migration publish --run .local\proto\migration-2 --out .local\proto\target-round-2
& $cli migration prepare --knowledge $sourceKnowledge --source-apk .local\proto\source.apk --target-apk .local\proto\target.apk --target-base .local\proto\target-round-2\knowledge.json --run .local\proto\migration-3
& $cli migration tasks --run .local\proto\migration-3 --state ALL
```

Inspect the ready targets, submit continuity Reviews with the existing Migration format, then publish and run `knowledge verify`. The target set and semantic names remain fixed by the source knowledge. Unresolved children preserve their last confirmed source instead of receiving guessed target bindings. The source's parent address cannot satisfy a target dependency.

Migration preserves matching's raw typed catalogue as an opaque artifact. Its relative path and digest appear in `report.json` under `methodArtifacts`; resolve the path from the publication directory. It does not call the Analysis method or reinterpret the catalogue. A wholly inherited round may carry these artifacts from its frozen target-base report, recording `methodArtifactSource`; fresh matching uses its own artifacts. Published copies remain usable after moving the package. Existing knowledge and Mapping verification remain independent of the catalogue projection.

## Verification boundary

The public regression uses self-authored protobuf input, generated Lite Java, real R8 renaming, installed CLI subprocesses, offline DEX checks and an independent R8 oracle. It covers valid field-number relationships, version changes, invalid/unknown metadata, explicit absent targets and publication protections. It needs the Android build SDK, not an emulator or installed APK. Fixture Reviews are predefined semantic truth and do not evaluate Agent judgment.

Private acceptance must separately read current source and target evidence, compare the source results with the selected manual targets, and verify the final Mapping. Rule stability and matching replay do not establish full schema or runtime behavioral equivalence.
