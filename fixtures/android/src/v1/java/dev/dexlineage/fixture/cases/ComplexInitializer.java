package dev.dexlineage.fixture.cases;

import dev.dexlineage.fixture.support.FixtureLogger;
import dev.dexlineage.fixture.support.LoggerFactory;
import dev.dexlineage.fixture.support.FixtureSignals;

/** Self-authored regression shape; readable names are transformed by R8. */
public final class ComplexInitializer {
    public static final FixtureLogger LOGGER;

    static {
        FixtureSignals.recordInitialization();
        LOGGER = LoggerFactory.create("FixtureScopeV1", "ComplexInitializer");
    }

    public String describe() {
        return LOGGER.format("after observable initialization");
    }
}
