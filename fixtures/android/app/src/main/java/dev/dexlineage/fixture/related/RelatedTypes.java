package dev.dexlineage.fixture.related;

// Self-authored raw DEX regression shapes. R8 renames every application symbol.
interface RecordValue {}
final class RequestRecord implements RecordValue {
    static final RequestRecord DEFAULT = new RequestRecord();
}
final class ResponseRecord implements RecordValue {
    static final ResponseRecord DEFAULT = new ResponseRecord();
}
interface WireContract {}
final class RequestMarshaller implements WireContract {
    final RecordValue value;
    RequestMarshaller(RecordValue value) { this.value = value; }
}
final class ResponseMarshaller implements WireContract {
    final RecordValue value;
    ResponseMarshaller(RecordValue value) { this.value = value; }
}
final class Marshallers {
    static WireContract request(RecordValue value) { return new RequestMarshaller(value); }
    static WireContract response(RecordValue value) { return new ResponseMarshaller(value); }
}
interface OtherWireContract {}
final class OtherMarshaller implements OtherWireContract {
    final RecordValue value;
    OtherMarshaller(RecordValue value) { this.value = value; }
}
final class Description {
    private final StringBuilder value = new StringBuilder();
    Description put(String label, Object field) { value.append(label).append('=').append(field); return this; }
    public String toString() { return value.toString(); }
}
final class RelatedCache {
    static volatile Object first;
    static volatile Object second;
}
final class WrongProducer {
    static String marker() { return "RelatedWrongProducer"; }
    static WrongProducer create(String first, String second) { return new WrongProducer(); }
}
final class ResearchOnly {
    int diagnosticCount;
    String explain() { return "Unconfigured research target"; }
}
