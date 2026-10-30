package dev.dexlineage.fixture.rounds;

final class NamedHandler implements SpecializedHandler {
    private long inspectionSequence;

    public String componentName() { return "RoundHandler"; }
    public String requestId() { return "round-request"; }

    // These overloads are unrelated to the no-argument interface roles.
    public String componentName(int diagnosticCode) { return HandlerDescription.render(diagnosticCode); }
    public String requestId(long sequence) { return HandlerDescription.render(sequence); }
    public String describe() { return HandlerDescription.render(++inspectionSequence); }
}

final class HandlerDescription {
    static String render(long sequence) { return "diagnostic-" + sequence; }
}
