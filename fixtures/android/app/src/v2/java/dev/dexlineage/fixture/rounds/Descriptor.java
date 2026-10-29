package dev.dexlineage.fixture.rounds;

final class Descriptor {
    final String fullName;
    final WireMarshaller response;
    final WireMarshaller request;
    Descriptor(String fullName, WireMarshaller response, WireMarshaller request) {
        this.fullName = fullName; this.response = response; this.request = request;
    }
    static DescriptorBuilder builder() { return new DescriptorBuilder(); }
    static String fullName(String service, String method) { return service + "/" + method; }
    public String toString() { return new Description().put("responseMarshaller", response).put("fullMethodName", fullName).put("requestMarshaller", request).toString(); }
}
final class DescriptorBuilder {
    String fullName;
    WireMarshaller response;
    WireMarshaller request;
    Descriptor build() { return new Descriptor(fullName, response, request); }
    void name(String value) { fullName = value; }
    Descriptor buildThroughHelper() { return DescriptorHelper.create(fullName, response, request); }
}
final class DescriptorHelper {
    static Descriptor create(String name, WireMarshaller response, WireMarshaller request) { return new Descriptor(name, response, request); }
}
// The construction moves from a descriptor helper into a stub in this version.
final class RpcStub {
    static Descriptor setter() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.name(Descriptor.fullName("fixture.Setter", "ReadRecord"));
        builder.response = new RecordMarshaller(ResponseRecord.DEFAULT);
        builder.request = new RecordMarshaller(RequestRecord.DEFAULT);
        return builder.build();
    }
    static Descriptor helper() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.fullName = Descriptor.fullName("fixture.Helper", "ReadRecord");
        builder.response = new RecordMarshaller(ResponseRecord.DEFAULT);
        builder.request = new RecordMarshaller(RequestRecord.DEFAULT);
        return builder.buildThroughHelper();
    }
    static Descriptor mixedDirect() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.fullName = Descriptor.fullName("fixture.Mixed", "ReadRecord");
        builder.response = new RecordMarshaller(ResponseRecord.DEFAULT);
        builder.request = new RecordMarshaller(RequestRecord.DEFAULT);
        return builder.build();
    }
    static Descriptor mixedSetter() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.name(Descriptor.fullName("fixture.Mixed", "ReadRecord"));
        builder.response = new RecordMarshaller(ResponseRecord.DEFAULT);
        builder.request = new RecordMarshaller(RequestRecord.DEFAULT);
        return builder.build();
    }
    static Descriptor read() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.fullName = Descriptor.fullName("fixture.Sample", "ReadRecord");
        builder.response = new RecordMarshaller(ResponseRecord.DEFAULT);
        builder.request = new RecordMarshaller(RequestRecord.DEFAULT);
        DescriptorCache.read = builder.build();
        return DescriptorCache.read;
    }
    static Descriptor split() {
        DescriptorBuilder named = Descriptor.builder();
        DescriptorBuilder unrelated = Descriptor.builder();
        named.fullName = Descriptor.fullName("fixture.Split", "ReadRecord");
        unrelated.response = new RecordMarshaller(ResponseRecord.DEFAULT);
        unrelated.request = new RecordMarshaller(RequestRecord.DEFAULT);
        DescriptorCache.split = named.build();
        return DescriptorCache.split;
    }
    static Descriptor swapped() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.fullName = Descriptor.fullName("fixture.Swapped", "ReadRecord");
        builder.response = new RecordMarshaller(RequestRecord.DEFAULT);
        builder.request = new RecordMarshaller(ResponseRecord.DEFAULT);
        DescriptorCache.swapped = builder.build();
        return DescriptorCache.swapped;
    }
}
