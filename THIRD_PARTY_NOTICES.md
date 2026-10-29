# Third-party notices

DexLineage's own source and public fixture source are licensed under [Apache-2.0](LICENSE). The installed CLI also contains the following unmodified libraries. This inventory covers the resolved runtime distribution for version 0.3.0; it does not change their licenses.

| Artifact | Version | License and accompanying text |
|---|---|---|
| `org.jetbrains.kotlin:kotlin-stdlib` | 2.2.10 | Apache-2.0; [license](LICENSE) |
| `org.jetbrains:annotations` | 13.0 | Apache-2.0; [license](LICENSE) |
| `io.github.skylot:jadx-core`, `jadx-dex-input`, `jadx-input-api`, `jadx-rename-mappings` | 1.5.0 | Apache-2.0; [license](LICENSE) |
| `com.google.code.gson:gson` | 2.10.1 | Apache-2.0; [license](LICENSE) |
| `net.fabricmc:mapping-io` | 0.6.1 | Apache-2.0; [license](LICENSE) |
| `com.android.tools.build:aapt2-proto` | 8.3.2-10880808 | Apache-2.0; [license](LICENSE), [upstream bundled notices](licenses/aapt2-proto-NOTICE.txt) |
| `com.google.guava:guava` | 33.1.0-jre | Apache-2.0; [license](LICENSE) |
| `com.google.guava:failureaccess` | 1.0.2 | Apache-2.0; [license](LICENSE) |
| `com.google.guava:listenablefuture` | 9999.0-empty-to-avoid-conflict-with-guava | Apache-2.0; [license](LICENSE); empty conflict-avoidance artifact |
| `com.google.errorprone:error_prone_annotations` | 2.26.1 | Apache-2.0; [license](LICENSE) |
| `com.google.code.findbugs:jsr305` | 3.0.2 | Apache-2.0; [license](LICENSE) |
| `org.checkerframework:checker-qual` | 3.42.0 | MIT; [copyright and license](licenses/checker-qual-LICENSE.txt) |
| `com.google.protobuf:protobuf-java` | 3.25.3 | BSD-3-Clause; [copyright and license](licenses/protobuf-LICENSE.txt) |
| `org.slf4j:slf4j-api`, `slf4j-simple` | 2.0.13 | MIT; [copyright and license](licenses/slf4j-LICENSE.txt) |
| `com.android.tools.smali:smali-baksmali`, `smali-dexlib2`, `smali-util` | 3.0.5 | BSD-3-Clause and Apache-2.0 components, with additional embedded notices; [complete upstream license file](licenses/smali-LICENSE.txt) |

License declarations were checked against the resolved artifacts' published POMs (including inherited parent POMs), embedded license files and the upstream release license. Copyright and permission notices are preserved in `licenses/`; the dependencies retain their own notices inside their original JARs as well.

The Gradle 8.11.1 Wrapper is included in the source checkout under Apache-2.0. [Gradle's distribution license](licenses/gradle-LICENSE.txt) and [NOTICE](licenses/gradle-NOTICE.txt) are preserved for reference, including its third-party acknowledgments. Gradle, Android SDK, AGP and R8 are build tools downloaded separately; they are not bundled in the DexLineage CLI distribution. Android SDK components retain their SDK license terms.

When changing dependency versions, inspect the actual `build/install/dexlineage/lib` contents and update this inventory and accompanying texts. Test-only libraries and CI Actions are not included in the CLI runtime.
