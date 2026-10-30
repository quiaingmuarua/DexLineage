# Public APK integration regression

The fixture suite preserves supported rules and invariants through the real Android toolchain, including schema-4 dependency rounds and compiled recipes. It complements the data-level unit tests and the private `realCaseTest`; it does not discover new rules or assess an Agent's ability to infer semantics.

## Run

Use JDK 21 and the committed root Wrapper. Install Android SDK command-line tools, `platforms;android-35` and `build-tools;35.0.0`, and accept the SDK licenses. Resolve the SDK through `ANDROID_HOME` or ignored root `local.properties` with a `sdk.dir` property. Local SDK paths and generated artifacts are not source inputs to commit.

```sh
./gradlew fixtureIntegrationTest
```

Use `.\gradlew.bat fixtureIntegrationTest` on Windows PowerShell. This explicit task builds the root-owned `:fixture-apk` Android application module, installs the CLI, validates the generated fixture, then runs the `fixture-integration` test group. Ordinary `test`, `check` and `build` exclude that group and need no Android SDK. `realCaseTest` remains an independent task with explicit private case configuration.

To build only the Android module:

```sh
./gradlew :fixture-apk:assembleV1Release :fixture-apk:assembleV2Release
```

For source editing, open the repository root in Android Studio and sync with the root Wrapper and JDK 21. `:fixture-apk` is a standard Android application module at `fixtures/android`, with `v1` and `v2` product flavors. IDE imports and explicit fixture tasks include the module; plain command-line JVM builds exclude it. Use `-PandroidFixtures=true` to include it explicitly or `-PandroidFixtures=false` for a JVM-only IDE import. Only the root `settings.gradle.kts` owns the module graph.

The fixtures are unsigned release APKs for static analysis; the suite does not install or execute them. AGP 8.10.1 supplies R8 8.10.24. The build uses compile/target SDK 35, build tools 35.0.0, min SDK 26 and Java 17 source/target on build JDK 21. `-dontshrink` and `-dontoptimize` retain the tested code shape, while R8 still renames classes, methods and fields. Separate name dictionaries force different symbols between versions. Original source filenames are replaced with a neutral marker; source code, R8 Mapping and the oracle are not packaged in the APK.

## Independent truth and production execution

`fixtures/cases.json` records expected source identities, field/call structure, captures, semantic aliases and per-version outcomes. The test reads R8's generated `mapping.txt` to translate those source identities into the expected DEX descriptors for that build. Sample preflight also checks R8's actual version/configuration, real renaming, version identity changes and the surviving field/call structure. A preflight failure is a fixture build failure, not a reason to relax the matcher or skip a case.

The installed production CLI runs in child processes. Test code does not call Analysis or Migration services to fabricate the flow and does not inject candidates or Resolutions. The same published knowledge file is handed to Migration. R8 Mapping and expected identities stay in test assertions and are never provided to matching or to JADX as rename inputs during matching.

Before accepting a task, the harness compares actual matching results with the independent oracle. It uses case-authored semantic conclusions for the Review and fills in only the real run, rule, Resolution and evidence references. These are deterministic test inputs, not simulated Agent reasoning. An actual analysis session still needs someone to read and judge the evidence.

Assertions cover:

- public and private static final loggers, captures distinct from confirmed aliases, and real factory/owner evidence;
- strings in other methods, non-final/instance fields and incompatible signatures that cannot supply a valid bound initialization;
- competitors outside discovery scope, duplicate component owners and unknown initialization that block uniqueness;
- tag, factory and obfuscated symbol changes across versions, missing signals and newly ambiguous targets;
- whole-rule replacement, same-APK ID continuity, preservation after failed updates, review identity validation and idempotency;
- missing Review, invalid ACCEPT attempts, process restart, saved publication replay and independent Mapping readback.

The multi-round fixture additionally uses self-authored logger, Handler and RPC models. The source-side simulated JADX annotations are derived from the independent R8 oracle and supplied only to the corpus importer; they are post-match assertions, not matcher parameters. It checks:

- a CLASS logger anchor followed by a full-identity METHOD factory anchor, with methods renamed between versions;
- multiple same-signature methods in one owner remaining ambiguous, and UNKNOWN prerequisites blocking downstream execution;
- className/requestId role extraction, interface implementations and constant-name returns;
- service/RPC, builder and request/response relationships, including marshaller factory versus constructor forms and relocation between Stub/helper owners;
- corpus targets remaining UNCONFIGURED when no rule exists, and imported source identity mismatches being rejected after matching;
- anchors publishing without Review but never entering Tiny, followed by reviewed class publication in later subprocess rounds;
- target-version anchors being resolved again, target-base continuation, stale dependency evidence rejection and same-APK knowledge preservation.

The related-RPC suite adds a two-round publication and migration flow for descriptor/builder/marshaller class roles. It covers `Object`-returning outer methods, declared interfaces versus concrete implementations, multiple complete constructions, and a uniquely identified method whose additional unknown construction must block downstream publication. The corpus research command is exercised on unconfigured targets; its evidence cannot be used as a matching-run Review. All published results use the same raw DEX consumption, R8 oracle assertions and independent JADX readback as the other suites.

The gRPC discovery suite starts with framework anchors and discovers service/RPC names from actual calls in both R8 versions. It checks grouping of shared Proto roles, repeated versus conflicting constructions, configuration-only calls, unresolved construction paths, exact service/RPC identity and canonical IDs carried from an explicit reference package. Reference truth is checked against the R8 oracle before a test Review is submitted. Published names still pass offline DEX consumption and independent JADX readback.

A deep Map/List configuration example preserves eight getter calls through R8 and passes the generated name through a self-authored boolean diagnostic guard before using it as a map key. It must remain a non-construction observation without poisoning unrelated RPCs; separate opaque-helper, field and return escapes remain UNKNOWN. The fixture checks the compiled getter and guard calls, not just different Java source text.

For an affected change, run the gRPC suite with `./gradlew :cli:fixtureIntegrationTest --tests '*GrpcDiscoveryIntegrationTest'`; the root aggregate task does not accept `--tests`. The unfiltered task in CI remains the complete public regression. Private theme acceptance uses `realCaseTest` with an explicit properties file whose `scenario=grpc-analysis` selects an Analysis-only manifest; it does not require inventing a Migration run. It independently reexecutes anchor/target matching and discovery, replays saved publications, checks declared new RPC pairs and referenced identities, and reads the final Mapping back through JADX.

CLASS and METHOD use separate entity identities. Assertions for methods compare the full original owner/name/signature obtained from the test oracle; checking only an owner class would miss incorrect method deduplication. Fixture semantics remain predetermined, and no public test has a private Messages target count or path.

Do not assert complete decompiled Java text, instruction offsets or APK hashes across builds. Assert identity, structure, captures, Resolution, review decisions and name application. APK digests still bind each actual run to its actual input.

## Consume published knowledge through raw DEX

The final static verification chain is:

```text
R8 APK -> production CLI matching -> published knowledge.json
       -> offline DEX lookup from knowledge bindings -> independent R8 oracle assertions
```

`PublishedKnowledgeDexCheck.verify(apk, knowledgeFile)` reads the on-disk publication and accepts no oracle, candidate list or expected owner. The test-side DEX index is shared with specimen preflight and cached by APK content hash. It retains DEX entry names and original class, field and full method identities. The consumer verifies the APK digest and resolves each confirmed class or support anchor at its exact published address. It returns actual fields and methods; the surrounding test separately checks them against independently mapped source identities. Reusing the input parser does not mean reusing matcher conclusions or trusting the saved `Resolution.matches` as newly observed facts.

Historical `unresolved` entries are recorded but never looked up as current bindings. Wrong APKs, wrong DEX entries, missing classes and nonexistent full method signatures fail consumption. A real but incorrect class can be read successfully; the outer oracle must reject that identity. Negative tests mutate only explicit test copies, never the original publication. The suite checks intermediate anchor-only publications, final Analysis/Migration publications, same-APK continuation, retained knowledge after failed updates and saved publication replay. JADX Mapping readback remains a separate check.

The consumer stays on the test classpath. It is not an APK runtime, a DEX interpreter, a new matcher or a field/method rename feature. Static member access and exact identity checks make no claim that application methods were executed or that two versions are behaviorally equivalent.

## Compiled version perturbations

The v2 fixture changes are deliberate, finite cases rather than a random mutation system. `FixturePerturbations` verifies their surviving DEX shape before matching:

- Unrelated fields, methods and differently typed overloads are added to logger and Handler owners.
- A business description method changes implementation while its locating logger relation stays intact.
- RPC construction changes field/constructor assignment order, request/response role order in descriptive text, marshaller factory wrapping to direct construction, and construction ownership from a descriptor helper to a stub.

Each assertion checks the relevant compiled members or call/assignment relationships. Changing Java declaration order alone is insufficient evidence; offsets and entire instruction sequences are not golden snapshots. Existing missing-string, duplicate-owner, unsupported-shape and cross-builder cases continue to check refusal behavior.

Successful source-to-target cases assert unchanged effective rule revisions, preserved semantic IDs and fresh target-APK Resolutions. Rule-replacement recovery remains a separate category. An internal change that removes a rule's declared feature is not required to keep matching, and an unsupported expression must not be accepted just to preserve a fixture success count.

## Add a regression case

1. Reduce the observed behavior to a self-authored Java example that is safe to publish. Use meaningful source class/member names. Preserve only the relevant structure; do not copy private APK code, proprietary strings, credentials or decompiled outputs.
2. Add the case to `fixtures/android/src/v1/java/` and `src/v2/java/`, or share unchanged support code in `src/main/java/`. Make version differences explicit. Keep the test within the existing matching capabilities unless a separate implementation task authorizes a new capability.
3. Declare both versions in `fixtures/cases.json` before reading actual candidate output. Record source owners, expected match outcome, logger fields/signatures and the intended semantic conclusion. Negative cases need explicit expected outcomes too.
4. Extend the CLI regression assertions for the new behavior, including its immutable dependency rounds when relevant. Use the R8 oracle for candidate identities, not observed candidates to derive an expected answer. Keep production rules free of expected obfuscated owners. Do not inject a synthetic Resolution or bypass the normal queue, submit or publish commands. Generated manual corpus inputs remain outside the matcher context.
5. Add compiled perturbation checks when the case claims stability under a version change, and published-knowledge/oracle assertions for the resulting entities. Run `fixtureIntegrationTest` and inspect preflight, consumption and command diagnostics. If R8 eliminated or changed the required structure, fix or re-scope the fixture transparently; do not add broad name-preservation rules or weaken matching just to regain a pass.
6. Commit only source, rules/oracle, tests and relevant docs. APKs, R8 output and CLI runs stay in build directories. New private experiments belong in `.runtime/`; repeatable private acceptance belongs in `.local/`.

## Diagnose a failure

| Stage | Inspect first | Meaning |
|---|---|---|
| SDK or Android build | Gradle error and installed SDK components | Environment or fixture compilation; no matching conclusion yet |
| Fixture preflight | R8 version, `mapping.txt`, `configuration.txt`, expected fields/calls | Test input no longer demonstrates the declared scenario |
| Compiled perturbation | `perturbations.json` and raw DEX members/calls | The claimed version change was absent or no longer has the intended shape |
| CLI command | `command.json`, `stdout.json`, `stderr.log` in the command's directory | Includes argument, exit-code and output evidence for the actual subprocess |
| Match assertion | Run snapshot and frozen Resolution, compared with `fixtures/cases.json` and R8 Mapping | Candidate/factor behavior changed |
| Review or publication | Submission payload, saved journal and publication report | A policy, evidence or conflict invariant changed |
| Offline consumption / oracle | Publication binding, returned DEX facts and expected R8 identities | Invalid published address or a real but incorrect entity |
| Mapping readback | `knowledge verify` command output and publication Mapping | Exported names failed independent JADX application |

Public command records and run packages are under `cli/build/fixture-integration/<run-id>/`. Each command gets a sequence-numbered directory under `commands/`. JUnit and HTML reports are under `cli/build/test-results/fixtureIntegrationTest/` and `cli/build/reports/tests/fixtureIntegrationTest/`. Generated Android files are under `fixtures/android/build/outputs/apk/` and `outputs/mapping/`. Commands have timeouts, failures retain diagnostics, and the suite does not silently retry or skip a failed case.

`cli/build/fixture-integration/apk-build.json` records elapsed time from SDK preflight through completion of both APK assembly tasks, excluding Gradle startup/configuration. It changes from STARTED to PASS only after both assemblies succeed; an interrupted or failed assembly leaves STARTED, with the failure in Gradle's task log. Suite reports include consumed class/method counts, rule and Resolution identities, oracle outcomes and command-stage timings. Offline DEX consumption and JADX readback are measured separately. Timings are observations for the current machine/cache state, not performance thresholds.

CI uses immutable Action commit references, JDK 21 and the committed Wrapper. JVM checks run on Ubuntu 24.04 and Windows; APK integration runs on Ubuntu 24.04. Jobs have a 20-minute timeout. Diagnostic artifacts are retained for 14 days and contain only explicit public build paths. Neither `.local/`, `.runtime/`, private Messages artifacts nor machine SDK configuration is uploaded. A cache miss may cost time, but must not change correctness.
