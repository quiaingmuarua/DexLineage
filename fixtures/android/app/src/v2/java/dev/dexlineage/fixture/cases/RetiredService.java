package dev.dexlineage.fixture.cases;

import dev.dexlineage.fixture.support.FixtureLogger;
import dev.dexlineage.fixture.support.LoggerFactory;
import dev.dexlineage.fixture.support.FixtureSignals;

/** Self-authored regression shape; readable names are transformed by R8. */
public final class RetiredService {
    public static final FixtureLogger LOGGER = LoggerFactory.build("FixtureScopeV2", "ReplacementSignal");

    public String describe() {
        return LOGGER.format("fixture event");
    }
}
