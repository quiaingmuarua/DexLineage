package dev.dexlineage.fixture.cases;

import dev.dexlineage.fixture.support.FixtureLogger;
import dev.dexlineage.fixture.support.LoggerFactory;
import dev.dexlineage.fixture.support.FixtureSignals;

/** Self-authored regression shape; readable names are transformed by R8. */
public final class MethodOnly {
    public String describe() {
        return LoggerFactory.create("FixtureScopeV1", "MethodOnly").format("method-local clue");
    }
}
