package dev.dexlineage.fixture.related;

final class RelatedDescriptor {
    final WireContract request;
    final WireContract response;
    final String fullName;
    RelatedDescriptor(WireContract request, WireContract response, String fullName) {
        this.request = request; this.response = response; this.fullName = fullName;
    }
    static String name(String service, String rpc) { return service + "/" + rpc; }
    public String toString() { return new Description().put("fullMethodName", fullName).put("requestMarshaller", request).put("responseMarshaller", response).toString(); }
}
final class RelatedBuilder {
    WireContract request;
    WireContract response;
    String fullName;
    RelatedDescriptor build() { return new RelatedDescriptor(request, response, fullName); }
    void name(String value) { fullName = value; }
}
final class OtherDescriptor {
    final OtherWireContract request;
    final OtherWireContract response;
    final String fullName;
    OtherDescriptor(OtherWireContract request, OtherWireContract response, String fullName) {
        this.request = request; this.response = response; this.fullName = fullName;
    }
    public String toString() { return new Description().put("fullMethodName", fullName).put("requestMarshaller", request).put("responseMarshaller", response).toString(); }
}
final class OtherBuilder {
    OtherWireContract request;
    OtherWireContract response;
    String fullName;
    OtherDescriptor build() { return new OtherDescriptor(request, response, fullName); }
}
final class RelatedRpcCases {
    static RelatedDescriptor getGroupInfo() {
        RelatedBuilder builder = new RelatedBuilder();
        builder.fullName = RelatedDescriptor.name("fixture.related.Group", "GetGroupInfo");
        builder.request = Marshallers.request(RequestRecord.DEFAULT);
        builder.response = Marshallers.response(ResponseRecord.DEFAULT);
        return builder.build();
    }
    // A complete relation must not hide a second unsupported relation in the same METHOD.
    static Object partlyUnsupported() {
        RelatedBuilder first = new RelatedBuilder();
        first.fullName = RelatedDescriptor.name("fixture.related.Partial", "GetGroupInfo");
        first.request = Marshallers.request(RequestRecord.DEFAULT);
        first.response = Marshallers.response(ResponseRecord.DEFAULT);
        RelatedCache.first = first.build();
        RelatedBuilder second = new RelatedBuilder();
        second.name(RelatedDescriptor.name("fixture.related.Partial", "GetGroupInfo"));
        second.request = Marshallers.request(RequestRecord.DEFAULT);
        second.response = Marshallers.response(ResponseRecord.DEFAULT);
        RelatedCache.second = second.build();
        return RelatedCache.first;
    }
    // Both constructions belong to this METHOD, but their three related roles differ.
    static Object multipleTypes() {
        RelatedBuilder first = new RelatedBuilder();
        first.fullName = RelatedDescriptor.name("fixture.related.Multiple", "GetGroupInfo");
        first.request = Marshallers.request(RequestRecord.DEFAULT);
        first.response = Marshallers.response(ResponseRecord.DEFAULT);
        RelatedCache.first = first.build();
        OtherBuilder second = new OtherBuilder();
        second.fullName = RelatedDescriptor.name("fixture.related.Multiple", "GetGroupInfo");
        second.request = new OtherMarshaller(RequestRecord.DEFAULT);
        second.response = new OtherMarshaller(ResponseRecord.DEFAULT);
        RelatedCache.second = second.build();
        return RelatedCache.first;
    }
    // Multiple sites for the same types still represent one entity for each role.
    static Object repeatedTypes() {
        RelatedBuilder first = new RelatedBuilder();
        first.fullName = RelatedDescriptor.name("fixture.related.Duplicate", "GetGroupInfo");
        first.request = Marshallers.request(RequestRecord.DEFAULT);
        first.response = Marshallers.response(ResponseRecord.DEFAULT);
        RelatedCache.first = first.build();
        RelatedBuilder second = new RelatedBuilder();
        second.fullName = RelatedDescriptor.name("fixture.related.Duplicate", "GetGroupInfo");
        second.request = Marshallers.request(RequestRecord.DEFAULT);
        second.response = Marshallers.response(ResponseRecord.DEFAULT);
        RelatedCache.second = second.build();
        return RelatedCache.first;
    }
    static Object servicePrefixDecoy() {
        OtherBuilder builder = new OtherBuilder();
        builder.fullName = RelatedDescriptor.name("fixture.related.GroupExtra", "GetGroupInfo");
        builder.request = new OtherMarshaller(RequestRecord.DEFAULT);
        builder.response = new OtherMarshaller(ResponseRecord.DEFAULT);
        return builder.build();
    }
    static Object rpcPrefixDecoy() {
        OtherBuilder builder = new OtherBuilder();
        builder.fullName = RelatedDescriptor.name("fixture.related.Group", "GetGroupInfoExtended");
        builder.request = new OtherMarshaller(RequestRecord.DEFAULT);
        builder.response = new OtherMarshaller(ResponseRecord.DEFAULT);
        return builder.build();
    }
}
