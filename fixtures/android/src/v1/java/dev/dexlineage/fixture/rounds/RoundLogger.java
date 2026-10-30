package dev.dexlineage.fixture.rounds;

final class RoundLogger {
    final String category;
    final String component;
    private RoundLogger(String category, String component) { this.category = category; this.component = component; }
    static RoundLogger create(String category, String component) { return new RoundLogger(category, component); }
    static RoundLogger create(String category, Class<?> type) { return new RoundLogger(category, type.getSimpleName()); }
    static String marker() { return "RoundLoggerAnchor"; }
}
final class LoggerBusiness {
    private static final RoundLogger LOGGER = RoundLogger.create("OldRoundScope", "RoundCache");
    String describe() { return LOGGER.component; }
}
final class AmbiguousLogger {
    static String marker() { return "AmbiguousLoggerAnchor"; }
    static AmbiguousLogger create(String tag, String component) { return new AmbiguousLogger(); }
    static AmbiguousLogger alternate(String tag, String component) { return new AmbiguousLogger(); }
}
