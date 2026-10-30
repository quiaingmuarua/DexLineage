package dev.dexlineage.fixture.cases;

import dev.dexlineage.fixture.support.FixtureLogger;
import dev.dexlineage.fixture.support.LoggerFactory;
import dev.dexlineage.fixture.support.FixtureSignals;

/** Self-authored regression shape; readable names are transformed by R8. */
public final class ExternalScopeCollision {
    public static final FixtureLogger LOGGER = LoggerFactory.create("ExternalScope", "ScopeCollision");

    public String describe() {
        return LOGGER.format("fixture event");
    }
}
