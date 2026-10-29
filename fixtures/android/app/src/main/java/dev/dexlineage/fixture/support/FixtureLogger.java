package dev.dexlineage.fixture.support;

/** A small observable logger shape; its component argument is an analysis clue. */
public final class FixtureLogger {
    private final String category;
    private final String component;

    public FixtureLogger(String category, String component) {
        this.category = category;
        this.component = component;
    }

    public String format(String message) {
        return new StringBuilder(category).append('/').append(component).append(": ").append(message).toString();
    }
}
