# DexLineage

DexLineage is a reusable APK analysis project. Version 0.4 provides two scenes:

- **Analysis:** import manual annotations or discover clues, combine built-in matching with compiled application strategies, resolve supporting anchors over immutable rounds, then review and publish class names.
- **Migration:** freeze existing semantic targets, resolve their rules and dependencies in another APK, review continuity, and publish new bindings with unresolved history retained.

Every new published binding requires a unique, definite result from actual code matching. Multiple candidates are invalid. An Agent can revise the rule and start another run, but cannot choose a candidate through Review text or a HIGH confidence declaration.

Supporting CLASS or METHOD anchors are mechanical matching results, not Rename entries. A UNIQUE anchor can be published without a semantic Review and consumed by a later round. Final class names require review of the owner and the supporting evidence chain. All output Mapping rows remain class-only.

## Build from a clean checkout

Requires JDK 21. Kotlin 2.2.10, Gradle Wrapper 8.11.1, JADX 1.5.0, Gson 2.10.1 and mapping-io 0.6.1 remain pinned. Module lockfiles record resolved dependencies. Initial dependency downloads require network access.

Linux/macOS:

```sh
git clone https://github.com/quiaingmuarua/DexLineage.git
cd DexLineage
./gradlew build installDist
build/install/dexlineage/bin/dexlineage --version
build/install/dexlineage/bin/dexlineage --help
```

Windows PowerShell, from the checkout:

```powershell
.\gradlew.bat build installDist
$cli = '.\build\install\dexlineage\bin\dexlineage.bat'
& $cli --version
& $cli --help
```

The launcher retains `build/install/dexlineage` and a 3 GiB maximum heap. Root `test`, `check`, `build`, `installDist` and `realCaseTest` aggregate the relevant module tasks. A focused test can run with `:analysis:test` or `:jadx:test`.

Normal `test` and `build` do not require Android SDK or any APKs. Keep repeatable private profiles, rules, runs, reviews and reports under ignored `.local/`; use ignored `.runtime/` for probes. APKs can stay at their existing paths. No installed JADX GUI, exported Gradle project or model API is required.

## Public APK integration regression

The public fixture suite builds readable, self-authored Java cases into two real APK versions using R8 name obfuscation. It then drives the installed production CLI through Analysis, review submission, publication, Migration, same-APK continuation and independent JADX Mapping readback. Published knowledge also drives a separate raw DEX lookup, whose returned class/member identities are checked against the independent R8 oracle. R8 shrinking and optimization are disabled; compiled version perturbations check that the existing rules survive changes to unrelated members, assignment order and supported construction shapes.

Install Android SDK command-line tools, configure `ANDROID_HOME`, then install the pinned components and accept their licenses:

```sh
export ANDROID_HOME=/path/to/android-sdk
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" 'platforms;android-35' 'build-tools;35.0.0'
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses
./gradlew fixtureIntegrationTest
```

On PowerShell, set `$env:ANDROID_HOME` to your SDK directory, use `sdkmanager.bat` with the same package names, and run `.\gradlew.bat fixtureIntegrationTest`. Alternatively set `sdk.dir=/path/to/android-sdk` in ignored `fixtures/android/local.properties` (use forward slashes on Windows). Missing SDK components fail the integration task; the suite is never silently skipped.

The fixture build is independent under `fixtures/android/`: AGP 8.10.1, its embedded R8 8.10.24, compile/target SDK 35, build tools 35.0.0, min SDK 26 and Java source/target 17. It uses the root Gradle Wrapper and JDK 21. No device, emulator, private APK, signing key, model service or repository secret is needed.

R8 Mapping is a test-only oracle for independent expected identities. The matcher receives APKs and rule data; it never receives that Mapping or expected candidate identities. Test Reviews contain predefined fixture semantics and real run/evidence references. They test protocol and publication behavior, **not Agent semantic judgment**.

The verification chain is **R8 APK → coding matching → published knowledge JSON → offline DEX verification → R8 oracle assertions**. The offline consumer takes only the APK and saved knowledge, resolves exact class/method addresses, and returns raw member facts. It does not execute DEX, infer missing bindings from historical entries, or use the oracle to find an entity. These checks establish static identity and rule-reuse regressions, not behavioral equivalence.

CI runs JVM checks on Ubuntu 24.04 and Windows, and the APK suite on Ubuntu 24.04. Public reports, command logs and generated fixture APK/Mapping/configuration are retained as CI artifacts for 14 days. See [fixture maintenance and failure diagnosis](docs/fixture-testing.md). Passing these cases does not establish coverage of all APKs or all obfuscators.

## Analyze an APK

Copy [the logger profile](examples/logger-profile.json) into `.local/` and set its business tag. It discovers field-initializer clues and can generate per-target rule drafts. No owner list or expected target belongs in the profile.

```powershell
& $cli analysis discover --apk 'D:\apks\current.apk' --profile .local\logger-profile.json --out .local\discovery-001
& $cli analysis prepare --apk 'D:\apks\current.apk' --rules .local\discovery-001\rules.json --run .local\analysis-001
& $cli analysis tasks --run .local\analysis-001 --state UNREVIEWED --offset 0 --limit 20
& $cli analysis inspect --run .local\analysis-001 --task 'task-key-1,task-key-2'
# The Agent reads the evidence and writes the appropriate review batch.
& $cli analysis submit --run .local\analysis-001 --review .local\analysis-review.json
& $cli analysis publish --run .local\analysis-001 --out .local\knowledge-v1
& $cli knowledge verify --knowledge .local\knowledge-v1\knowledge.json --apk 'D:\apks\current.apk' --work .runtime\verify-v1
```

Discovery can return many owners: this is normal scope exploration. Its clues and rule drafts cannot publish names. `prepare` executes each target's rules over the entire APK, including owners outside the discovery scope, and freezes a Resolution. A discovery-linked unique result must also agree with that lead's original owner.

Discovery is optional. An Agent can write an [Analysis rules file](examples/analysis-rules.json) from an observed feature and pass it directly to `analysis prepare`. An item contains a stable task key, optional existing `semanticId`, optional name suggestion and locator list; it cannot supply an expected obfuscated target. A corrected name does not rewrite captured strings or locators.

Use `tasks --state INVALID` and `inspect` to investigate invalid results. Their candidates and diagnostics remain available; they do not require an artificial Review. Even a unique result needs actual semantic review before acceptance. Field-initializer naming requires owner and internal factory code; plain string-use rules require owner code and their actual matching evidence.

## Import manual work and execute dependency rounds

Import a JADX `projectVersion=1` annotation project into a new corpus directory:

```powershell
& $cli analysis import-jadx --apk 'D:\apks\current.apk' --project 'D:\apks\current.apk.jadx' --out .local\manual-corpus
& $cli analysis targets --corpus .local\manual-corpus\corpus.json --limit 20
```

The corpus preserves class, field, method and local annotations. Class annotations become stable targets; members and local positions remain research context. Import validates original class/member references. A class target's source identity is checked after matching; it is never passed to the matcher as an expected-owner filter. Importing an annotation does not approve a name for publication. The 544 annotations / 238 classes in the private Messages audit describe that local case, not a public default or a coverage target.

An Analysis rule item can refer to a corpus target using `corpusTargetId`. Pass `--corpus` to `analysis prepare`; `analysis targets --corpus ... --run ...` shows every manual target, including `UNCONFIGURED` items and failures. New discoveries outside the corpus are reported separately.

Copy [the multi-round example](examples/multiround-rules.json) and replace its public marker/component strings with observed inputs. It defines a logger class anchor, a current-version factory METHOD anchor and a class target that uses that factory:

```powershell
& $cli analysis prepare --apk 'D:\apks\current.apk' --rules .local\round-rules.json --corpus .local\manual-corpus\corpus.json --run .local\round-1
& $cli analysis tasks --run .local\round-1 --state ALL
& $cli analysis publish --run .local\round-1 --out .local\knowledge-round-1
& $cli analysis prepare --apk 'D:\apks\current.apk' --rules .local\round-rules.json --corpus .local\manual-corpus\corpus.json --base-knowledge .local\knowledge-round-1\knowledge.json --run .local\round-2
& $cli analysis publish --run .local\round-2 --out .local\knowledge-round-2
```

Continue with a new run and the latest base until the required class tasks are ready for `inspect / submit / publish`. This example needs another round before the class can use its newly published factory. `prepare` never consumes anchors created within that same execution. Missing resolved prerequisites are `WAITING_DEPENDENCY`, with no fabricated Resolution. `inspect --task 'anchor:logger-factory'` reads an anchor's code; ordinary task IDs read class candidates and their dependency evidence.

The compile-time registry provides Messages-oriented logger, Handler-name and RPC/Proto strategies. They take configuration and structured APK facts, not hardcoded obfuscated answers. [The RPC example](examples/rpc-rules.json) demonstrates one descriptor METHOD anchor feeding request and response class targets. Real application tags, service lists and manual names belong in `.local`; the strategy code and self-authored fixtures are public.

## Continue Analysis on existing knowledge

Pass a knowledge package from the same APK with `--base-knowledge`:

```powershell
& $cli analysis prepare --apk 'D:\apks\current.apk' --rules .local\additional-rules.json --base-knowledge .local\knowledge-v1\knowledge.json --run .local\analysis-002
# Inspect and review the new or changed tasks, then publish a complete revision.
& $cli analysis publish --run .local\analysis-002 --out .local\knowledge-v1-revision-2
```

The base knowledge ID is frozen. Existing current-version entities retain their `semanticId`; names are not identity keys. Successful updates and new confirmations are combined with unchanged base entries. A failed rule attempt, rejected update or conflicting proposal does not erase the prior valid binding, name or rule. This version does not move an existing semantic ID to another entity in the same APK.

Unchanged confirmations and supporting proofs can be inherited when their rules, implementation and dependency proofs are unchanged. An inherited class does not need another Review. Updating an anchor invalidates reuse of downstream proofs that refer to its previous revision; old published packages are preserved.

An explicitly selected pending item whose last binding belongs to the current APK can be retried. Historical pending entries from other APKs are carried forward; Analysis does not automatically investigate or claim them by matching a name.

## Migrate knowledge

Pass the published knowledge file and accompanying evidence directly to Migration:

```powershell
& $cli migration prepare --knowledge .local\knowledge-v1\knowledge.json --source-apk 'D:\apks\old.apk' --target-apk 'D:\apks\new.apk' --run .local\migration-001
& $cli migration tasks --run .local\migration-001 --state UNREVIEWED --offset 0 --limit 20
& $cli migration inspect --run .local\migration-001 --task 'semantic-id-1,semantic-id-2'
& $cli migration submit --run .local\migration-001 --review .local\migration-review.json
& $cli migration publish --run .local\migration-001 --out .local\knowledge-v2
& $cli knowledge verify --knowledge .local\knowledge-v2\knowledge.json --apk 'D:\apks\new.apk' --work .runtime\verify-v2
```

Migration only creates tasks for confirmed semantic targets in the source knowledge. It preserves their names and keeps unresolved knowledge with its last confirmed source. The default confidence threshold is HIGH; `prepare --min-confidence MEDIUM` freezes another threshold without relaxing uniqueness or identity checks.

Source anchors supply rule definitions, not target-version bindings. Migration resolves them again on the target APK. After publishing one round, keep the original `--knowledge` and source/target APKs fixed and pass the prior target package through `--target-base`:

```powershell
& $cli migration prepare --knowledge .local\knowledge-v1\knowledge.json --source-apk 'D:\apks\old.apk' --target-apk 'D:\apks\new.apk' --target-base .local\knowledge-v2-round-1\knowledge.json --run .local\migration-002
```

The target base must belong to that same source knowledge and target APK. It preserves earlier target confirmations while enabling later dependency rounds; it does not replace the frozen source target set.

Supply an [override file](examples/migration-overrides.json) with `migration prepare --rules ...` and a new run directory to revise rules. Each override replaces that target's entire active locator set; unlisted targets keep their rules. Unknown semantic IDs are rejected. A target-version rule need not match the source APK. Accepted migration publishes the rule revision actually used for the new binding.

Multiple candidates cannot be resolved by Review. `migration inspect --candidate 'semantic-id=Lx/a;,Lx/b;'` remains available for reading selected candidates; it grants no publication eligibility.

## Reviews, revisions and packages

Use `tasks` to obtain task, Resolution and rule revision IDs. Both Review formats bind `resolutionId` and `ruleRevisionId`; they do not choose an entity. Analysis may propose a name. Migration judges whether the existing name and responsibility continue. See [the exact formats](docs/architecture.md#reviews).

Class review states are `UNREVIEWED`, `ACCEPTED`, `REJECTED`, `DEFERRED` and `INVALID`. Execution separately reports `EXECUTED`, `WAITING_DEPENDENCY` or `INHERITED`; task lists also contain supporting anchor tasks. Match results identify `UNIQUE`, `NO_MATCH`, `AMBIGUOUS` or `UNKNOWN`. Scan failure is an execution error. Listing creates no claims or leases; one coordinator submits sequentially.

Review batches save atomically. Identical resubmission is idempotent; replacing a Review requires its current revision in `supersedes`. Modified rules create a new execution, and old Review identities cannot pretend to describe its new Resolution.

Every publication uses a new directory containing:

- `knowledge.json`: schema 4, class bindings, supporting anchors, active rules, dependency proofs, parent knowledge reference, review provenance and unresolved history.
- `mapping.tiny`: class-only Tiny v2 `obfuscated` → `named` mappings.
- `report.json`: task outcomes, active rules, diagnostics and published review revisions.
- `evidence/`: required Java/Smali files with content hashes.

Keep the package together. Matching proofs include their frozen dependencies; all referenced code is copied into the package, including historical proof evidence. Reproduce a same-run publication after later reviews:

```powershell
& $cli analysis publish --run .local\analysis-001 --at .local\knowledge-v1\report.json --out .local\knowledge-v1-replay
& $cli migration publish --run .local\migration-001 --at .local\knowledge-v2\report.json --out .local\knowledge-v2-replay
```

This replays saved decisions. Re-executing matching from APKs and fixed rules is a separate check; publication replay does not establish that matching has been rerun.

## Upgrade historical knowledge explicitly

```powershell
& $cli knowledge import-v03 --knowledge .local\v03-package\knowledge.json --apk 'D:\apks\current.apk' --out .local\v04-imported
& $cli knowledge import-v02 --knowledge .local\v02-package\knowledge.json --apk 'D:\apks\current.apk' --out .local\v02-upgraded
& $cli knowledge import-s1 --output .local\s1-output --run .local\s1-run --out .local\s1-imported
```

The importers validate the old knowledge package, report, Mapping and code evidence, then rerun rules against the supplied APK. Only a unique result that remains the original binding can retain the validated historical semantic review. Ambiguous, unknown, missing or differently bound results become pending with their historical source preserved. Broken packages or missing required proof are input errors. S1 conversion retains its original consistency checks and applies the same uniqueness gate.

A v0.3 package may inherit an entry whose original Review lives in an earlier publication. Supply those packages explicitly with `--history <manifest.json>`; the importer does not guess directories or search private history. The manifest is `{"schemaVersion":4,"knowledgeFiles":["relative/path/to/knowledge.json"]}`, with paths relative to the manifest. The importer validates the cited package chain and preserves its provenance. Old files are never rewritten.

Old v0.2 Migration reports did not record their configurable confidence threshold. Their confirmed reviews therefore must be HIGH to prove they satisfied every supported old threshold; a weaker review lacks the required policy proof and is an input error. Old single-version reports retained the threshold in their profile and are checked against that value.

Evidence completeness means verifiable files, identities, hashes and review references. It does not require every Java method to decompile: acknowledged limitations remain visible. Historical packages are never changed in place. Old `bootstrap` and unprefixed S1 commands return guidance; [case.json](examples/case.json) is only a legacy reference.

## Verification and limits

`knowledge verify` opens fresh DEX-only JADX with the DEX and rename-mappings plugins in read mode. It checks Mapping contents, original identities, displayed names and declarations. A successful build is not this proof.

The explicit `realCaseTest` task requires local case properties; normal builds exclude it. The real case uses existing APKs and Agent-authored reviews, tests fresh matching separately from publication replay, and checks invalid ambiguity, same-APK continuation, failed-update retention, legacy upgrade and Mapping readback. It does not fabricate semantic reviews or require historical success counts.

For the v0.4 multi-round acceptance runner, use a local properties file:

```properties
scenario=v04
caseManifest=manifest.json
acceptanceRoot=acceptance
```

The schema-4 manifest records `corpus`, ordered `analysisRounds` and `migrationRounds` (each with `run` and `output`), optional `shapeRounds`, and `upgradedV03` package paths. Paths resolve relative to the manifest. Optional `expectedAnnotationCounts`, `expectedClassTargets`, `requiredStrategyIds` and `requiredPublishedRules` make the local acceptance requirements explicit. The runner freshly checks producer anchors before using them as dependencies, reexecutes matching, replays each saved publication, then independently reads back final class mappings. Keep the manifest and all private results under `.local`.

On Windows, very large selections can exceed the `.bat` command-line limit. Page the task list into smaller batches, or invoke the same installed CLI without the batch wrapper:

```powershell
java -Xmx3g '-Dorg.slf4j.simpleLogger.defaultLogLevel=warn' -cp 'build/install/dexlineage/lib/*' dev.dexlineage.cli.MainKt migration inspect --run .local/my-case/target-run --task $taskIds
```

Use a new schema-4 case configuration; old v0.3 runs must be upgraded explicitly before reuse. The test's required property keys are documented by its [source](cli/src/test/kotlin/dev/dexlineage/cli/RealCaseTest.kt), and paths resolve relative to the properties file. A case configuration points to actual prepared, reviewed and published artifacts, not a candidate-answer list.

```powershell
.\gradlew.bat realCaseTest "-PcaseProperties=.local/my-case/acceptance.properties"
```

Keep case configuration and acceptance records in `.local/`. Evidence-volume metrics describe generated/cached files, not automatic measurement of Agent reading. Partial code and the review's unverified scope remain visible.

Commands emit JSON on stdout and diagnostics on stderr. Exit codes are `0` for completion, including invalid/pending items; `2` for invalid inputs or Review submissions; and `1` for execution failure.

This version supports the two existing locator kinds and compiled strategies for current-version method signatures, logger calls, Handler naming and RPC/Proto roles. Unknown code shapes remain visible instead of being treated as proven matches. The registry is compiled into the application; there is no dynamic plugin/script loader, member renaming, GUI/MCP or model API. See [architecture and contracts](docs/architecture.md) for rule and knowledge boundaries.

## License

DexLineage and its public fixture source use [Apache-2.0](LICENSE). The CLI distribution includes [third-party notices](THIRD_PARTY_NOTICES.md) and the corresponding license texts. Version 0.4.0 is distributed as source; release tags and GitHub Releases are separate actions.
