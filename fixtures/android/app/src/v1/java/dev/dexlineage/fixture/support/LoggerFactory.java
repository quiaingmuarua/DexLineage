package dev.dexlineage.fixture.support;

public final class LoggerFactory {
    public static FixtureLogger create(String category, String component) {
        return new FixtureLogger(category, component);
    }

    public static FixtureLogger createCounted(String category, String component, int count) {
        return new FixtureLogger(category, new StringBuilder(component).append(count).toString());
    }
}
