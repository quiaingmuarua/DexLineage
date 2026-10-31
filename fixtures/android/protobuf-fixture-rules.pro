# RawMessageInfo contains generated field-name strings. With optimization disabled,
# preserve just these generated member names so reflection metadata remains valid.
# Classes and methods, including generated Proto classes/methods, are still renamed.
-keepclassmembers class dev.dexlineage.fixture.proto.** {
    <fields>;
}
