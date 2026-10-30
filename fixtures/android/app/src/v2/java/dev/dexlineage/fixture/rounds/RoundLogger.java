package dev.dexlineage.fixture.rounds;

final class RoundLogger {
    final String category;
    final String component;
    private long diagnosticSequence;
    private RoundLogger(String category, String component) { this.category = category; this.component = component; }
    static RoundLogger construct(String category, String component) { return new RoundLogger(category, component); }
    static RoundLogger construct(String category, Class<?> type) { return new RoundLogger(category, type.getSimpleName()); }
    // A real overload, deliberately outside the two-String locator signature.
    static RoundLogger construct(String category, String component, int diagnosticCode) {
        RoundLogger logger = new RoundLogger(category, component);
        logger.diagnosticSequence = diagnosticCode;
        return logger;
    }
    long nextDiagnosticSequence() { return ++diagnosticSequence; }
    static String marker() { return "RoundLoggerAnchor"; }
}
final class LoggerBusiness {
    private int inspectionCount;
    private static final RoundLogger LOGGER = RoundLogger.construct("NewRoundScope", "RoundCache");
    String describe() { return LoggerDescription.render(LOGGER.component, inspectionCount); }
    String describe(int extra) { return LoggerDescription.render(LOGGER.component, inspectionCount + extra); }
}
final class LoggerDescription {
    static String render(String component, int count) { return component + ":" + count; }
}
final class AmbiguousLogger {
    static String marker() { return "AmbiguousLoggerAnchor"; }
    static AmbiguousLogger construct(String tag, String component) { return new AmbiguousLogger(); }
    static AmbiguousLogger another(String tag, String component) { return new AmbiguousLogger(); }
}
