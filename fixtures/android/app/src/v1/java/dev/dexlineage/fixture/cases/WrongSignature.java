package dev.dexlineage.fixture.cases;

import dev.dexlineage.fixture.support.FixtureLogger;
import dev.dexlineage.fixture.support.LoggerFactory;
import dev.dexlineage.fixture.support.FixtureSignals;

/** Self-authored regression shape; readable names are transformed by R8. */
public final class WrongSignature {
    public static final FixtureLogger LOGGER = LoggerFactory.createCounted("FixtureScopeV1", "WrongSignature", 7);

    public String describe() {
        return LOGGER.format("fixture event");
    }
}
