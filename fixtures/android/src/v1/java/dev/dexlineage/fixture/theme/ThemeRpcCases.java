package dev.dexlineage.fixture.theme;

final class ThemeDescriptor {
    final ThemeWire request;
    final ThemeWire response;
    final String fullName;
    ThemeDescriptor(ThemeWire request, ThemeWire response, String fullName) {
        this.request = request; this.response = response; this.fullName = fullName;
    }
    static String name(String service, String rpc) { return service + "/" + rpc; }
    static String reversed(String service, String rpc) { return rpc + "/" + service; }
    static String differentSeparator(String service, String rpc) { return service + ":" + rpc; }
    static String unrelatedOverload(String service, int code) { return service + "/" + code; }
    public String toString() { return new ThemeDescription().put("fullMethodName", fullName).put("requestMarshaller", request).put("responseMarshaller", response).toString(); }
}
final class ThemeBuilder {
    ThemeWire request;
    ThemeWire response;
    String fullName;
    ThemeDescriptor build() { return new ThemeDescriptor(request, response, fullName); }
    void unsupportedName(String value) { fullName = value; }
}

// Two qualifying methods on this single owner must remain two METHOD entities.
final class AmbiguousDescriptor {
    final ThemeWire request;
    final ThemeWire response;
    final String fullName;
    AmbiguousDescriptor(ThemeWire request, ThemeWire response, String fullName) {
        this.request = request; this.response = response; this.fullName = fullName;
    }
    static String name(String service, String rpc) { return service + "/" + rpc; }
    static String alternate(String service, String rpc) { return service + "/" + rpc; }
    public String toString() { return new ThemeDescription().put("fullMethodName", fullName).put("requestMarshaller", request).put("responseMarshaller", response).toString(); }
}
final class AmbiguousBuilder {
    ThemeWire request;
    ThemeWire response;
    String fullName;
    AmbiguousDescriptor build() { return new AmbiguousDescriptor(request, response, fullName); }
}

final class ThemeRpcCases {
    static ThemeDescriptor seed() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Seed");
        builder.request = ThemeMarshallers.request(SeedRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(SeedResponse.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor groupState() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "FetchState");
        builder.request = ThemeMarshallers.request(GroupRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(GroupResponse.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor registrationState() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Registration", "FetchState");
        builder.request = ThemeMarshallers.request(RegistrationRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(RegistrationResponse.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor sharedSend() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Messaging", "Send");
        builder.request = ThemeMarshallers.request(SharedRecord.DEFAULT);
        builder.response = ThemeMarshallers.response(SharedRecord.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor sharedReport() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Abuse", "Report");
        builder.request = ThemeMarshallers.request(SharedRecord.DEFAULT);
        builder.response = ThemeMarshallers.response(AbuseResponse.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor duplicateFirst() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Duplicate");
        builder.request = ThemeMarshallers.request(DuplicateRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(DuplicateResponse.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor duplicateSecond() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Duplicate");
        builder.request = ThemeMarshallers.request(DuplicateRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(DuplicateResponse.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor conflictFirst() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Conflicting");
        builder.request = ThemeMarshallers.request(ConflictFirstRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(ConflictFirstResponse.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor conflictSecond() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Conflicting");
        builder.request = ThemeMarshallers.request(ConflictSecondRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(ConflictSecondResponse.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor knownPart() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "PartlyUnknown");
        builder.request = ThemeMarshallers.request(UnknownRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(UnknownResponse.DEFAULT);
        return builder.build();
    }
    static ThemeDescriptor outsideScope() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Outside", "FetchState");
        builder.request = ThemeMarshallers.request(OutsideRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(OutsideResponse.DEFAULT);
        return builder.build();
    }
    // A supported map/config use consumes the name without returning or storing it in a field.
    static Object configurationOnly() {
        java.util.Map<String, String> config = new java.util.HashMap<>();
        config.put(ThemeDescriptor.name("fixture.theme.Group", "ConfigurationOnly"), "configuration-value");
        return config;
    }
    // Real configuration-parser shape: nested lookups exceed the bounded value-expression depth.
    static Object deepConfiguration(java.util.Map<String, Object> input) {
        java.util.Map<?, ?> section = (java.util.Map<?, ?>) input.get("methodConfig");
        java.util.List<?> entries = (java.util.List<?>) section.get("entries");
        java.util.Map<?, ?> entry = (java.util.Map<?, ?>) entries.get(0);
        java.util.List<?> methods = (java.util.List<?>) entry.get("methods");
        java.util.Map<?, ?> method = (java.util.Map<?, ?>) methods.get(0);
        java.util.Map<?, ?> definition = (java.util.Map<?, ?>) method.get("definition");
        String service = (String) definition.get("service");
        String rpc = (String) definition.get("method");
        String name = ThemeDescriptor.name(service, rpc);
        java.util.Map<String, Object> result = new java.util.HashMap<>();
        ThemeChecks.check(!result.containsKey(name), "duplicate method", name);
        result.put(name, entry);
        return result;
    }
    static Object opaqueUse() {
        ThemeOpaqueUse.accept(ThemeDescriptor.name("fixture.theme.Group", "OpaqueHelper"));
        return null;
    }
    // Escaped names are unresolved possible constructions, not confidently excluded config calls.
    static String escapedName() {
        String value = ThemeDescriptor.name("fixture.theme.Group", "EscapedName");
        ThemeConfiguration.fullName = value;
        return value;
    }
    // A potential descriptor remains unresolved when assignment escapes supported facts.
    static Object unknownPart() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.unsupportedName(ThemeDescriptor.name("fixture.theme.Group", "PartlyUnknown"));
        builder.request = ThemeMarshallers.request(UnknownRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(UnknownResponse.DEFAULT);
        return builder.build();
    }
    static Object ambiguousSeed() {
        AmbiguousBuilder builder = new AmbiguousBuilder();
        builder.fullName = AmbiguousDescriptor.name("fixture.theme.Ambiguous", "Seed");
        builder.request = ThemeMarshallers.request(SeedRequest.DEFAULT);
        builder.response = ThemeMarshallers.response(SeedResponse.DEFAULT);
        return builder.build();
    }
}
