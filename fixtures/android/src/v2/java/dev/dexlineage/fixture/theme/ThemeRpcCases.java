package dev.dexlineage.fixture.theme;

final class ThemeDescriptor {
    final String fullName;
    final ThemeWire response;
    final ThemeWire request;
    ThemeDescriptor(String fullName, ThemeWire response, ThemeWire request) {
        this.fullName = fullName; this.response = response; this.request = request;
    }
    static String name(String service, String rpc) { return service + "/" + rpc; }
    static String reversed(String service, String rpc) { return rpc + "/" + service; }
    static String differentSeparator(String service, String rpc) { return service + ":" + rpc; }
    static String unrelatedOverload(String service, int code) { return service + "/" + code; }
    public String toString() { return new ThemeDescription().put("responseMarshaller", response).put("fullMethodName", fullName).put("requestMarshaller", request).toString(); }
}
final class ThemeBuilder {
    String fullName;
    ThemeWire response;
    ThemeWire request;
    ThemeDescriptor build() { return new ThemeDescriptor(fullName, response, request); }
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
    static Object seed() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Seed");
        builder.response = new ThemeResponseMarshaller(SeedResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(SeedRequest.DEFAULT);
        return builder.build();
    }
    static Object groupState() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "FetchState");
        builder.response = new ThemeResponseMarshaller(GroupResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(GroupRequest.DEFAULT);
        return builder.build();
    }
    static Object registrationState() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Registration", "FetchState");
        builder.response = new ThemeResponseMarshaller(RegistrationResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(RegistrationRequest.DEFAULT);
        return builder.build();
    }
    static Object sharedSend() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Messaging", "Send");
        builder.response = new ThemeResponseMarshaller(SharedRecord.DEFAULT);
        builder.request = new ThemeRequestMarshaller(SharedRecord.DEFAULT);
        return builder.build();
    }
    static Object sharedReport() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Abuse", "Report");
        builder.response = new ThemeResponseMarshaller(AbuseResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(SharedRecord.DEFAULT);
        return builder.build();
    }
    static Object duplicateFirst() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Duplicate");
        builder.response = new ThemeResponseMarshaller(DuplicateResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(DuplicateRequest.DEFAULT);
        return builder.build();
    }
    static Object duplicateSecond() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Duplicate");
        builder.response = new ThemeResponseMarshaller(DuplicateResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(DuplicateRequest.DEFAULT);
        return builder.build();
    }
    static Object conflictFirst() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Conflicting");
        builder.response = new ThemeResponseMarshaller(ConflictFirstResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(ConflictFirstRequest.DEFAULT);
        return builder.build();
    }
    static Object conflictSecond() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "Conflicting");
        builder.response = new ThemeResponseMarshaller(ConflictSecondResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(ConflictSecondRequest.DEFAULT);
        return builder.build();
    }
    static Object knownPart() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Group", "PartlyUnknown");
        builder.response = new ThemeResponseMarshaller(UnknownResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(UnknownRequest.DEFAULT);
        return builder.build();
    }
    static Object outsideScope() {
        ThemeBuilder builder = new ThemeBuilder();
        builder.fullName = ThemeDescriptor.name("fixture.theme.Outside", "FetchState");
        builder.response = new ThemeResponseMarshaller(OutsideResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(OutsideRequest.DEFAULT);
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
        builder.response = new ThemeResponseMarshaller(UnknownResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(UnknownRequest.DEFAULT);
        return builder.build();
    }
    static Object ambiguousSeed() {
        AmbiguousBuilder builder = new AmbiguousBuilder();
        builder.fullName = AmbiguousDescriptor.name("fixture.theme.Ambiguous", "Seed");
        builder.response = new ThemeResponseMarshaller(SeedResponse.DEFAULT);
        builder.request = new ThemeRequestMarshaller(SeedRequest.DEFAULT);
        return builder.build();
    }
}
