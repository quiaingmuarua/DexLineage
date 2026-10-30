package dev.dexlineage.fixture.rounds;

// Self-authored dependency and descriptor shapes. No source names are kept by R8.
interface HandlerContract {
    String componentName();
    String requestId();
}
interface SpecializedHandler extends HandlerContract {}
final class NamedHandler implements SpecializedHandler {
    public String componentName() { return "RoundHandler"; }
    public String requestId() { return "round-request"; }
}
final class DuplicateHandlerOne implements HandlerContract {
    public String componentName() { return "DuplicateHandler"; }
    public String requestId() { return "first-request"; }
}
final class DuplicateHandlerTwo implements SpecializedHandler {
    public String componentName() { return "DuplicateHandler"; }
    public String requestId() { return "second-request"; }
}
final class NotAHandler {
    public String componentName() { return "RoundHandler"; }
}
final class Lifecycle {
    public static void execute(HandlerContract handler) {
        RoundLog.emit("RoundScope", "Executing fixture handler: class=%s request=%s", handler.componentName(), handler.requestId());
    }
}
final class RoundLog {
    static volatile String last;
    public static void emit(String tag, String format, Object... args) {
        last = tag + String.format(format, args);
    }
}
interface UnknownContract {
    String componentName();
    String requestId();
}
final class UnknownHandler implements UnknownContract {
    public String componentName() { return System.getProperty("fixture.handler.name"); }
    public String requestId() { return "unknown-request"; }
}
final class KnownUnknownPeer implements UnknownContract {
    public String componentName() { return "UnknownPeer"; }
    public String requestId() { return "known-request"; }
}
final class UnknownLifecycle {
    public static void execute(UnknownContract handler) {
        RoundLog.emit("RoundScope", "Uncertain fixture handler: class=%s request=%s", handler.componentName(), handler.requestId());
    }
}
final class EscapedLifecycle {
    public static void execute(HandlerContract handler) {
        Object[] values = new Object[] { handler.componentName(), handler.requestId() };
        ArgumentMutator.replaceFirst(values, handler.requestId());
        RoundLog.emit("RoundScope", "Escaped fixture handler: class=%s request=%s", values);
    }
}
final class ArgumentMutator {
    public static void replaceFirst(Object[] values, Object replacement) { values[0] = replacement; }
}
final class UnconfiguredTarget { public int count() { return 17; } }

interface RecordValue {}
final class RequestRecord implements RecordValue {
    static final RequestRecord DEFAULT = new RequestRecord();
    public long sequence;
}
final class ResponseRecord implements RecordValue {
    static final ResponseRecord DEFAULT = new ResponseRecord();
    public boolean available;
}
interface WireMarshaller {}
final class RecordMarshaller implements WireMarshaller {
    final RecordValue defaultValue;
    RecordMarshaller(RecordValue value) { defaultValue = value; }
}
final class RecordMarshallers {
    static WireMarshaller wrap(RecordValue value) { return new RecordMarshaller(value); }
}
final class Description {
    private final StringBuilder text = new StringBuilder();
    Description put(String name, Object value) { text.append(name).append('=').append(value); return this; }
    public String toString() { return text.toString(); }
}
final class DescriptorCache {
    static volatile Descriptor read;
    static volatile Descriptor split;
    static volatile Descriptor swapped;
}
