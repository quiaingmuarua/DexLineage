package dev.dexlineage.fixture.rounds;

final class Descriptor {
    final WireMarshaller request;
    final WireMarshaller response;
    final String fullName;
    Descriptor(WireMarshaller request, WireMarshaller response, String fullName) {
        this.request = request; this.response = response; this.fullName = fullName;
    }
    static DescriptorBuilder builder() { return new DescriptorBuilder(); }
    static String fullName(String service, String method) { return service + "/" + method; }
    public String toString() { return new Description().put("fullMethodName", fullName).put("requestMarshaller", request).put("responseMarshaller", response).toString(); }
}
final class DescriptorBuilder {
    WireMarshaller request;
    WireMarshaller response;
    String fullName;
    Descriptor build() { return new Descriptor(request, response, fullName); }
    void name(String value) { fullName = value; }
    Descriptor buildThroughHelper() { return DescriptorHelper.create(request, response, fullName); }
}
final class DescriptorHelper {
    static Descriptor create(WireMarshaller request, WireMarshaller response, String name) { return new Descriptor(request, response, name); }
}
final class RpcDescriptors {
    static Descriptor setter() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.name(Descriptor.fullName("fixture.Setter", "ReadRecord"));
        builder.request = RecordMarshallers.wrap(RequestRecord.DEFAULT);
        builder.response = RecordMarshallers.wrap(ResponseRecord.DEFAULT);
        return builder.build();
    }
    static Descriptor helper() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.fullName = Descriptor.fullName("fixture.Helper", "ReadRecord");
        builder.request = RecordMarshallers.wrap(RequestRecord.DEFAULT);
        builder.response = RecordMarshallers.wrap(ResponseRecord.DEFAULT);
        return builder.buildThroughHelper();
    }
    static Descriptor mixedDirect() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.fullName = Descriptor.fullName("fixture.Mixed", "ReadRecord");
        builder.request = RecordMarshallers.wrap(RequestRecord.DEFAULT);
        builder.response = RecordMarshallers.wrap(ResponseRecord.DEFAULT);
        return builder.build();
    }
    static Descriptor mixedSetter() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.name(Descriptor.fullName("fixture.Mixed", "ReadRecord"));
        builder.request = RecordMarshallers.wrap(RequestRecord.DEFAULT);
        builder.response = RecordMarshallers.wrap(ResponseRecord.DEFAULT);
        return builder.build();
    }
    static Descriptor read() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.fullName = Descriptor.fullName("fixture.Sample", "ReadRecord");
        builder.request = RecordMarshallers.wrap(RequestRecord.DEFAULT);
        builder.response = RecordMarshallers.wrap(ResponseRecord.DEFAULT);
        DescriptorCache.read = builder.build();
        return DescriptorCache.read;
    }
    static Descriptor split() {
        DescriptorBuilder named = Descriptor.builder();
        DescriptorBuilder unrelated = Descriptor.builder();
        named.fullName = Descriptor.fullName("fixture.Split", "ReadRecord");
        unrelated.request = RecordMarshallers.wrap(RequestRecord.DEFAULT);
        unrelated.response = RecordMarshallers.wrap(ResponseRecord.DEFAULT);
        DescriptorCache.split = named.build();
        return DescriptorCache.split;
    }
    static Descriptor swapped() {
        DescriptorBuilder builder = Descriptor.builder();
        builder.fullName = Descriptor.fullName("fixture.Swapped", "ReadRecord");
        builder.request = RecordMarshallers.wrap(ResponseRecord.DEFAULT);
        builder.response = RecordMarshallers.wrap(RequestRecord.DEFAULT);
        DescriptorCache.swapped = builder.build();
        return DescriptorCache.swapped;
    }
}
