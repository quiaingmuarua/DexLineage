package dev.dexlineage.fixture.cases;

import dev.dexlineage.fixture.support.FixtureLogger;
import dev.dexlineage.fixture.support.LoggerFactory;
import dev.dexlineage.fixture.support.FixtureSignals;

/** Self-authored regression shape; readable names are transformed by R8. */
public final class CrossFieldDecoy {
    public static final FixtureLogger STATIC_OTHER = LoggerFactory.build("ExternalScope", "OtherComponent");
    public final FixtureLogger INSTANCE_CLUE = LoggerFactory.build("FixtureScopeV2", "CrossFieldDecoy");

    public String describe() {
        return LoggerFactory.build("FixtureScopeV2", "CrossFieldDecoy").format(STATIC_OTHER.format("separate bindings"));
    }
}
