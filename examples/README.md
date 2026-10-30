# Examples

`rpc-related-rules.json` demonstrates a two-round descriptor METHOD anchor followed by reviewed descriptor, builder and declared marshaller-interface class targets. Related rules take only `role`; service/RPC/label configuration stays with the producer. Use `analysis research --corpus ... --target ... --out ...` to inspect manual source targets before authoring such rules. Research output cannot replace a matched run's evidence.

All current examples use `schemaVersion: 4` and illustrative public strings. Copy them into `.local/` before adding application-specific data. They contain no expected obfuscated targets or private paths.

## Discovery profile

`logger-profile.json` is a field-initializer discovery strategy. Set both `discovery.anchor` and the argument-0 exact `value` to your business tag. It requires:

- Original STATIC and FINAL flags, with unrestricted visibility; private loggers can match.
- A static initializer call with two String parameters and a return type equal to its field type.
- A constant tag at argument 0, a constant component at argument 1 and assignment to the bound owner's field.

`nameCapture` selects the component suggestion. The optional `locatorTemplate` drafts a per-target locator using that capture. This example keeps the component literal but does not fix the old tag, factory name or obfuscated field name. The confirmed alias is not a template input.

Run `analysis discover --apk ... --profile ... --out ...`, then pass the generated `rules.json` to `analysis prepare`. Discovery itself does not prove uniqueness. Preparation executes each rule across the entire APK; a discovery-linked result must remain the original owner. Removing `nameCapture` and/or `locatorTemplate` is supported when only clues are wanted.

## Direct Analysis rule

`analysis-rules.json` shows a direct current-APK rule using `string-use`. Replace the literal with an observed exact method string. `key` is a task identity; `proposedName` is only a naming suggestion. For updating known same-APK knowledge, add its actual `semanticId` and use `--base-knowledge`.

Multiple matching classes make the result invalid. Supplying an alias, reviewing one candidate or rejecting another does not resolve it. Improve the rule and use a new run if necessary.

## Migration override

`migration-overrides.json` replaces the locator set for one existing semantic ID. Replace the illustrative ID with an ID from the input knowledge; unknown IDs are rejected. Optional `expectedRevision` can pin the source entry's current rule revision. Use `migration prepare --rules ...` with a new run directory.

The replacement list is the complete active set for that target, not an additional vote. If a broad old locator remains as an OR alternative and still finds multiple entities, the result stays invalid.

See [rule and Review contracts](../docs/architecture.md) for precise fields. Agent interpretation still needs actual code evidence after unique matching.

## Compiled strategies and rounds

`multiround-rules.json` combines an independent string anchor, a `builtin.method-signature` METHOD anchor and a `messages.logger-fields` class target. Replace the marker and captured component values with observed data. The code will locate the current-version factory method; no old obfuscated method name is supplied. `requires` maps local roles to anchor keys.

Prepare and publish a first run, then prepare a new run with `--base-knowledge` pointing at that publication. Repeat as needed: an anchor produced by one prepare cannot enable a downstream rule in the same prepare. A UNIQUE anchor can publish without Review; a class target still needs `inspect / submit` before its name can publish. Use `inspect --task anchor:logger-factory` to read a supporting method's owner evidence. Missing resolved dependencies are WAITING_DEPENDENCY, not NO_MATCH.

`rpc-rules.json` uses illustrative service `example.Service` and RPC `Read` to show a descriptor METHOD anchor feeding request/response CLASS targets. The recipe identifies roles within one construction and supports the observed factory/constructor variants. It does not infer a helper's name from whichever class contains the strings.

Both files may be combined with a manual corpus imported by `analysis import-jadx`. Put the target's actual `targetId` in an item's `corpusTargetId` and pass `--corpus` to prepare. Original manual identities are checked after matching. The target ledger reports all corpus classes even when rules cover only a subset.

After source publication, Migration consumes the same knowledge file. Keep `--knowledge` fixed across target rounds and use `--target-base` for the previous target publication. Generic and Messages-specific strategy implementations are compiled into the project. Real application configuration remains local; these examples contain only public illustrative values.

## Historical reference

`case.json` is a **legacy S1 schema-version-1 reference**. Current Analysis/Migration commands do not consume it. Upgrade a completed S1 run and output explicitly with `knowledge import-s1`; upgrade schema 2 knowledge with `knowledge import-v02`, or schema 3 knowledge with `knowledge import-v03`. For inherited v0.3 entries, supply earlier Review-bearing packages through the explicit history manifest when requested. The original inputs remain unchanged. See [upgrade commands](../README.md#upgrade-historical-knowledge-explicitly).
