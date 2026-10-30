package dev.dexlineage.fixture.related;

final class RelatedDescriptor {
    final String fullName;
    final WireContract response;
    final WireContract request;
    RelatedDescriptor(String fullName, WireContract response, WireContract request) {
        this.fullName = fullName; this.response = response; this.request = request;
    }
    static String name(String service, String rpc) { return service + "/" + rpc; }
    public String toString() { return new Description().put("responseMarshaller", response).put("fullMethodName", fullName).put("requestMarshaller", request).toString(); }
}
final class RelatedBuilder {
    String fullName;
    WireContract response;
    WireContract request;
    RelatedDescriptor build() { return new RelatedDescriptor(fullName, response, request); }
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
    static Object getGroupInfo() {
        RelatedBuilder builder = new RelatedBuilder();
        builder.fullName = RelatedDescriptor.name("fixture.related.Group", "GetGroupInfo");
        builder.response = new ResponseMarshaller(ResponseRecord.DEFAULT);
        builder.request = new RequestMarshaller(RequestRecord.DEFAULT);
        return builder.build();
    }
    // A complete relation must not hide a second unsupported relation in the same METHOD.
    static Object partlyUnsupported() {
        RelatedBuilder first = new RelatedBuilder();
        first.fullName = RelatedDescriptor.name("fixture.related.Partial", "GetGroupInfo");
        first.response = new ResponseMarshaller(ResponseRecord.DEFAULT);
        first.request = new RequestMarshaller(RequestRecord.DEFAULT);
        RelatedCache.first = first.build();
        RelatedBuilder second = new RelatedBuilder();
        second.name(RelatedDescriptor.name("fixture.related.Partial", "GetGroupInfo"));
        second.response = new ResponseMarshaller(ResponseRecord.DEFAULT);
        second.request = new RequestMarshaller(RequestRecord.DEFAULT);
        RelatedCache.second = second.build();
        return RelatedCache.first;
    }
    // Both constructions belong to this METHOD, but their three related roles differ.
    static Object multipleTypes() {
        RelatedBuilder first = new RelatedBuilder();
        first.fullName = RelatedDescriptor.name("fixture.related.Multiple", "GetGroupInfo");
        first.response = new ResponseMarshaller(ResponseRecord.DEFAULT);
        first.request = new RequestMarshaller(RequestRecord.DEFAULT);
        RelatedCache.first = first.build();
        OtherBuilder second = new OtherBuilder();
        second.fullName = RelatedDescriptor.name("fixture.related.Multiple", "GetGroupInfo");
        second.response = new OtherMarshaller(ResponseRecord.DEFAULT);
        second.request = new OtherMarshaller(RequestRecord.DEFAULT);
        RelatedCache.second = second.build();
        return RelatedCache.first;
    }
    // Multiple sites for the same types still represent one entity for each role.
    static Object repeatedTypes() {
        RelatedBuilder first = new RelatedBuilder();
        first.fullName = RelatedDescriptor.name("fixture.related.Duplicate", "GetGroupInfo");
        first.response = new ResponseMarshaller(ResponseRecord.DEFAULT);
        first.request = new RequestMarshaller(RequestRecord.DEFAULT);
        RelatedCache.first = first.build();
        RelatedBuilder second = new RelatedBuilder();
        second.fullName = RelatedDescriptor.name("fixture.related.Duplicate", "GetGroupInfo");
        second.response = new ResponseMarshaller(ResponseRecord.DEFAULT);
        second.request = new RequestMarshaller(RequestRecord.DEFAULT);
        RelatedCache.second = second.build();
        return RelatedCache.first;
    }
    static Object servicePrefixDecoy() {
        OtherBuilder builder = new OtherBuilder();
        builder.fullName = RelatedDescriptor.name("fixture.related.GroupExtra", "GetGroupInfo");
        builder.response = new OtherMarshaller(ResponseRecord.DEFAULT);
        builder.request = new OtherMarshaller(RequestRecord.DEFAULT);
        return builder.build();
    }
    static Object rpcPrefixDecoy() {
        OtherBuilder builder = new OtherBuilder();
        builder.fullName = RelatedDescriptor.name("fixture.related.Group", "GetGroupInfoExtended");
        builder.response = new OtherMarshaller(ResponseRecord.DEFAULT);
        builder.request = new OtherMarshaller(RequestRecord.DEFAULT);
        return builder.build();
    }
}
