package dev.dexlineage.fixture.support;

/** The write is intentionally observable and precedes a later field assignment. */
public final class FixtureSignals {
    public static volatile int initializations;

    public static void recordInitialization() {
        initializations++;
    }
}
