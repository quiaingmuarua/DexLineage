package dev.dexlineage.fixture.theme;

// Self-authored protocol shapes; R8 supplies all obfuscated identities.
interface ThemeRecord {}
final class SeedRequest implements ThemeRecord { static final SeedRequest DEFAULT = new SeedRequest(); }
final class SeedResponse implements ThemeRecord { static final SeedResponse DEFAULT = new SeedResponse(); }
final class GroupRequest implements ThemeRecord {
    static final GroupRequest DEFAULT = new GroupRequest();
    String identityClue() { return "theme-canonical-request"; }
}
final class GroupResponse implements ThemeRecord { static final GroupResponse DEFAULT = new GroupResponse(); }
final class RegistrationRequest implements ThemeRecord { static final RegistrationRequest DEFAULT = new RegistrationRequest(); }
final class RegistrationResponse implements ThemeRecord { static final RegistrationResponse DEFAULT = new RegistrationResponse(); }
final class SharedRecord implements ThemeRecord { static final SharedRecord DEFAULT = new SharedRecord(); }
final class AbuseResponse implements ThemeRecord { static final AbuseResponse DEFAULT = new AbuseResponse(); }
final class DuplicateRequest implements ThemeRecord { static final DuplicateRequest DEFAULT = new DuplicateRequest(); }
final class DuplicateResponse implements ThemeRecord { static final DuplicateResponse DEFAULT = new DuplicateResponse(); }
final class ConflictFirstRequest implements ThemeRecord { static final ConflictFirstRequest DEFAULT = new ConflictFirstRequest(); }
final class ConflictFirstResponse implements ThemeRecord { static final ConflictFirstResponse DEFAULT = new ConflictFirstResponse(); }
final class ConflictSecondRequest implements ThemeRecord { static final ConflictSecondRequest DEFAULT = new ConflictSecondRequest(); }
final class ConflictSecondResponse implements ThemeRecord { static final ConflictSecondResponse DEFAULT = new ConflictSecondResponse(); }
final class UnknownRequest implements ThemeRecord { static final UnknownRequest DEFAULT = new UnknownRequest(); }
final class UnknownResponse implements ThemeRecord { static final UnknownResponse DEFAULT = new UnknownResponse(); }
final class OutsideRequest implements ThemeRecord { static final OutsideRequest DEFAULT = new OutsideRequest(); }
final class OutsideResponse implements ThemeRecord { static final OutsideResponse DEFAULT = new OutsideResponse(); }

interface ThemeWire {}
final class ThemeRequestMarshaller implements ThemeWire {
    final ThemeRecord value;
    ThemeRequestMarshaller(ThemeRecord value) { this.value = value; }
}
final class ThemeResponseMarshaller implements ThemeWire {
    final ThemeRecord value;
    ThemeResponseMarshaller(ThemeRecord value) { this.value = value; }
}
final class ThemeMarshallers {
    static ThemeWire request(ThemeRecord value) { return new ThemeRequestMarshaller(value); }
    static ThemeWire response(ThemeRecord value) { return new ThemeResponseMarshaller(value); }
}
final class ThemeDescription {
    private final StringBuilder value = new StringBuilder();
    ThemeDescription put(String label, Object field) { value.append(label).append('=').append(field); return this; }
    public String toString() { return value.toString(); }
}
final class ThemeConfiguration {
    static volatile Object first;
    static volatile Object second;
    static String fullName;
}
