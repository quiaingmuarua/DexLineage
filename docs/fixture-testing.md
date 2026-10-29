# Public APK integration regression

The fixture suite preserves already supported rules and invariants through the real Android toolchain. It complements the data-level unit tests and the private `realCaseTest`; it does not discover new rules or assess an Agent's ability to infer semantics.

## Run

Use JDK 21 and the committed root Wrapper. Install Android SDK command-line tools, `platforms;android-35` and `build-tools;35.0.0`, and accept the SDK licenses. Resolve the SDK through `ANDROID_HOME` or ignored `fixtures/android/local.properties` with a `sdk.dir` property. Local SDK paths and generated artifacts are not source inputs to commit.

```sh
./gradlew fixtureIntegrationTest
```

Use `.\gradlew.bat fixtureIntegrationTest` on Windows PowerShell. This explicit task builds the independent `fixtures/android/` project, installs the CLI, validates the generated fixture, then runs the `fixture-integration` test group. Ordinary `test`, `check` and `build` exclude that group and need no Android SDK. `realCaseTest` remains an independent task with explicit private case configuration.

To investigate the Android build independently:

```sh
./gradlew -p fixtures/android :app:assembleV1Release :app:assembleV2Release
```

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

Do not assert complete decompiled Java text, instruction offsets or APK hashes across builds. Assert identity, structure, captures, Resolution, review decisions and name application. APK digests still bind each actual run to its actual input.

## Add a regression case

1. Reduce the observed behavior to a self-authored Java example that is safe to publish. Use meaningful source class/member names. Preserve only the relevant structure; do not copy private APK code, proprietary strings, credentials or decompiled outputs.
2. Add the case to `fixtures/android/app/src/v1/java/` and `src/v2/java/`, or share unchanged support code in `src/main/java/`. Make version differences explicit. Keep the test within the existing matching capabilities unless a separate implementation task authorizes a new capability.
3. Declare both versions in `fixtures/cases.json` before reading actual candidate output. Record source owners, expected match outcome, logger fields/signatures and the intended semantic conclusion. Negative cases need explicit expected outcomes too.
4. Extend the CLI regression assertions for the new behavior. Use the R8 oracle for candidate identities, not observed candidates to derive an expected answer. Keep production rules free of expected obfuscated owners. Do not inject a synthetic Resolution or bypass the normal queue, submit or publish commands.
5. Run `fixtureIntegrationTest` and inspect preflight and command diagnostics. If R8 eliminated or changed the required structure, fix or re-scope the fixture transparently; do not add broad name-preservation rules or weaken matching just to regain a pass.
6. Commit only source, rules/oracle, tests and relevant docs. APKs, R8 output and CLI runs stay in build directories. New private experiments belong in `.runtime/`; repeatable private acceptance belongs in `.local/`.

## Diagnose a failure

| Stage | Inspect first | Meaning |
|---|---|---|
| SDK or Android build | Gradle error and installed SDK components | Environment or fixture compilation; no matching conclusion yet |
| Fixture preflight | R8 version, `mapping.txt`, `configuration.txt`, expected fields/calls | Test input no longer demonstrates the declared scenario |
| CLI command | `command.json`, `stdout.json`, `stderr.log` in the command's directory | Includes argument, exit-code and output evidence for the actual subprocess |
| Match assertion | Run snapshot and frozen Resolution, compared with `fixtures/cases.json` and R8 Mapping | Candidate/factor behavior changed |
| Review or publication | Submission payload, saved journal and publication report | A policy, evidence or conflict invariant changed |
| Mapping readback | `knowledge verify` command output and publication Mapping | Exported names failed independent JADX application |

Public command records and run packages are under `cli/build/fixture-integration/<run-id>/`. Each command gets a sequence-numbered directory under `commands/`. JUnit and HTML reports are under `cli/build/test-results/fixtureIntegrationTest/` and `cli/build/reports/tests/fixtureIntegrationTest/`. Generated Android files are under `fixtures/android/app/build/outputs/apk/` and `outputs/mapping/`. Commands have timeouts, failures retain diagnostics, and the suite does not silently retry or skip a failed case.

CI uses immutable Action commit references, JDK 21 and the committed Wrapper. JVM checks run on Ubuntu 24.04 and Windows; APK integration runs on Ubuntu 24.04. Jobs have a 20-minute timeout. Diagnostic artifacts are retained for 14 days and contain only explicit public build paths. Neither `.local/`, `.runtime/`, private Messages artifacts nor machine SDK configuration is uploaded. A cache miss may cost time, but must not change correctness.
