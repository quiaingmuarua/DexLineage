# DexLineage

DexLineage is a reusable APK analysis project. Version 0.3 provides two scenes:

- **Analysis:** discover clues or supply executable rules, identify a unique entity, review its meaning, then create or extend knowledge for that APK.
- **Migration:** freeze existing semantic targets, execute rules against another APK, review continuity, and publish new bindings with unresolved history retained.

Every new published binding requires a unique, definite result from actual code matching. Multiple candidates are invalid. An Agent can revise the rule and start another run, but cannot choose a candidate through Review text or a HIGH confidence declaration.

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

The public fixture suite builds readable, self-authored Java cases into two real APK versions using R8 name obfuscation. It then drives the installed production CLI through Analysis, review submission, publication, Migration, same-APK continuation and independent JADX Mapping readback. R8 shrinking and optimization are disabled; this suite checks the existing rules and publication constraints under real symbol changes.

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

## Continue Analysis on existing knowledge

Pass a knowledge package from the same APK with `--base-knowledge`:

```powershell
& $cli analysis prepare --apk 'D:\apks\current.apk' --rules .local\additional-rules.json --base-knowledge .local\knowledge-v1\knowledge.json --run .local\analysis-002
# Inspect and review the new or changed tasks, then publish a complete revision.
& $cli analysis publish --run .local\analysis-002 --out .local\knowledge-v1-revision-2
```

The base knowledge ID is frozen. Existing current-version entities retain their `semanticId`; names are not identity keys. Successful updates and new confirmations are combined with unchanged base entries. A failed rule attempt, rejected update or conflicting proposal does not erase the prior valid binding, name or rule. This version does not move an existing semantic ID to another entity in the same APK.

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

Supply an [override file](examples/migration-overrides.json) with `migration prepare --rules ...` and a new run directory to revise rules. Each override replaces that target's entire active locator set; unlisted targets keep their rules. Unknown semantic IDs are rejected. A target-version rule need not match the source APK. Accepted migration publishes the rule revision actually used for the new binding.

Multiple candidates cannot be resolved by Review. `migration inspect --candidate 'semantic-id=Lx/a;,Lx/b;'` remains available for reading selected candidates; it grants no publication eligibility.

## Reviews, revisions and packages

Use `tasks` to obtain task, Resolution and rule revision IDs. Both Review formats bind `resolutionId` and `ruleRevisionId`; they do not choose an entity. Analysis may propose a name. Migration judges whether the existing name and responsibility continue. See [the exact formats](docs/architecture.md#reviews).

Task states are `UNREVIEWED`, `ACCEPTED`, `REJECTED`, `DEFERRED` and `INVALID`. Match results separately identify `UNIQUE`, `NO_MATCH`, `AMBIGUOUS` or `UNKNOWN`. Scan failure is an execution error. Listing creates no claims or leases; one coordinator submits sequentially.

Review batches save atomically. Identical resubmission is idempotent; replacing a Review requires its current revision in `supersedes`. Modified rules create a new execution, and old Review identities cannot pretend to describe its new Resolution.

Every publication uses a new directory containing:

- `knowledge.json`: schema 3, bindings, active rule revisions, matching proofs, parent knowledge reference, review provenance and unresolved history.
- `mapping.tiny`: class-only Tiny v2 `obfuscated` → `named` mappings.
- `report.json`: task outcomes, active rules, diagnostics and published review revisions.
- `evidence/`: required Java/Smali files with content hashes.

Keep the package together. Matching proofs are embedded in knowledge; referenced code is copied into the package. Reproduce a same-run publication after later reviews:

```powershell
& $cli analysis publish --run .local\analysis-001 --at .local\knowledge-v1\report.json --out .local\knowledge-v1-replay
& $cli migration publish --run .local\migration-001 --at .local\knowledge-v2\report.json --out .local\knowledge-v2-replay
```

This replays saved decisions. Re-executing matching from APKs and fixed rules is a separate check; publication replay does not establish that matching has been rerun.

## Upgrade historical knowledge explicitly

```powershell
& $cli knowledge import-v02 --knowledge .local\v02-package\knowledge.json --apk 'D:\apks\current.apk' --out .local\v03-imported
& $cli knowledge import-s1 --output .local\s1-output --run .local\s1-run --out .local\s1-imported
```

The v0.2 importer validates the knowledge package, report, Mapping and code evidence, then reruns its rules against the supplied APK. Only a unique result that remains the original binding can retain the validated historical semantic review. Ambiguous, unknown, missing or differently bound results become pending with their historical source preserved. Broken packages or missing required proof are input errors. S1 conversion retains its original consistency checks and applies the same uniqueness gate.

Old v0.2 Migration reports did not record their configurable confidence threshold. Their confirmed reviews therefore must be HIGH to prove they satisfied every supported old threshold; a weaker review lacks the required policy proof and is an input error. Old single-version reports retained the threshold in their profile and are checked against that value.

Evidence completeness means verifiable files, identities, hashes and review references. It does not require every Java method to decompile: acknowledged limitations remain visible. Historical packages are never changed in place. Old `bootstrap` and unprefixed S1 commands return guidance; [case.json](examples/case.json) is only a legacy reference.

## Verification and limits

`knowledge verify` opens fresh DEX-only JADX with the DEX and rename-mappings plugins in read mode. It checks Mapping contents, original identities, displayed names and declarations. A successful build is not this proof.

The explicit `realCaseTest` task requires local case properties; normal builds exclude it. The real case uses existing APKs and Agent-authored reviews, tests fresh matching separately from publication replay, and checks invalid ambiguity, same-APK continuation, failed-update retention, legacy upgrade and Mapping readback. It does not fabricate semantic reviews or require historical success counts.

Paths resolve relative to the properties file. Use forward slashes for Windows paths:

```properties
analysisRun=analysis-source
analysisOutput=knowledge-source
migrationRun=migration-target
migrationOutput=knowledge-target
continuationRun=analysis-target-continued
continuationOutput=knowledge-target-continued
failedUpdateRun=analysis-failed-update
failedUpdateOutput=knowledge-after-failed-update
upgradedV02Output=upgraded-v02
v02Knowledge=legacy-v02/knowledge.json
acceptanceRoot=acceptance
```

These paths point to actual prepared/reviewed/published case artifacts. The test freshly reruns discovery and matching, replays publications, checks continuation IDs and failed-update preservation, checks the legacy upgrade gate, then independently reads back source and final target Mapping files.

```powershell
.\gradlew.bat realCaseTest "-PcaseProperties=.local/v03/messages/acceptance.properties"
```

Keep case configuration and acceptance records in `.local/`. Evidence-volume metrics describe generated/cached files, not automatic measurement of Agent reading. Partial code and the review's unverified scope remain visible.

Commands emit JSON on stdout and diagnostics on stderr. Exit codes are `0` for completion, including invalid/pending items; `2` for invalid inputs or Review submissions; and `1` for execution failure.

This version supports exact DEX method-string anchors and field-initializer factors. It does not add arbitrary scripts, custom Handler registration, member renaming, GUI/MCP or model calls. See [architecture and contracts](docs/architecture.md) for rule and knowledge boundaries.

## License

DexLineage and its public fixture source use [Apache-2.0](LICENSE). The CLI distribution includes [third-party notices](THIRD_PARTY_NOTICES.md) and the corresponding license texts. Version 0.3.0 is distributed as source; this first delivery does not create a release tag or a GitHub Release.
