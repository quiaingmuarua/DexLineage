package dev.dexlineage.fixture.support;

public final class LoggerFactory {
    public static FixtureLogger build(String category, String component) {
        return new FixtureLogger(category, component);
    }

    public static FixtureLogger buildCounted(String category, String component, int count) {
        return new FixtureLogger(category, new StringBuilder(component).append(count).toString());
    }
}
