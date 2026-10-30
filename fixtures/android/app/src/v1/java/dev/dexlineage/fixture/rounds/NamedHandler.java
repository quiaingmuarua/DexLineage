package dev.dexlineage.fixture.rounds;

final class NamedHandler implements SpecializedHandler {
    public String componentName() { return "RoundHandler"; }
    public String requestId() { return "round-request"; }
}
