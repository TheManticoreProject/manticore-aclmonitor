package acls

import (
	"strings"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/ldap"
)

// TestResolverAnswersFromTheCheapestSource checks the order the resolver tries: a
// well-known SID needs no lookup and is never qualified with the domain, an indexed
// one is qualified, and an unknown one resolves to nothing rather than to a guess.
func TestResolverAnswersFromTheCheapestSource(t *testing.T) {
	resolver := testResolver(map[string]string{sidBob: "svc_backup"})

	testCases := []struct {
		name string
		sid  string
		want string
	}{
		{"well-known SID", sidEveryone, "Everyone"},
		{"indexed SID", sidBob, "MANTICORE.local\\svc_backup"},
		{"unknown SID", sidAlice, ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := resolver.Name(testCase.sid); got != testCase.want {
				t.Errorf("Name(%s) = %q, want %q", testCase.sid, got, testCase.want)
			}
		})
	}
}

// TestResolverDisplayAlwaysShowsTheSid checks that a name never replaces the SID: the
// name is what the operator reads, the SID is what the ACE holds and what a follow-up
// query has to be written against.
func TestResolverDisplayAlwaysShowsTheSid(t *testing.T) {
	resolver := testResolver(map[string]string{sidBob: "svc_backup"})

	if got, want := resolver.Display(sidBob), "MANTICORE.local\\svc_backup ("+sidBob+")"; got != want {
		t.Errorf("Display(named) = %q, want %q", got, want)
	}
	if got := resolver.Display(sidAlice); got != sidAlice {
		t.Errorf("Display(unnamed) = %q, want the bare SID %q", got, sidAlice)
	}
}

// TestResolverWithoutADomainDoesNotQualify checks the diff-mode case where the stored
// reading recorded no domain: a name is shown unqualified rather than prefixed with an
// empty domain.
func TestResolverWithoutADomainDoesNotQualify(t *testing.T) {
	snapshot := NewSnapshot()
	snapshot.Identities = map[string]string{sidBob: "svc_backup"}
	resolver := NewResolver(snapshot, "", nil, nil)

	if got := resolver.Name(sidBob); got != "svc_backup" {
		t.Errorf("Name = %q, want the unqualified name", got)
	}
}

// TestResolverCachesAMiss checks that a SID the directory does not know is looked up
// once and not once per cycle, for the lifetime of the run.
func TestResolverCachesAMiss(t *testing.T) {
	resolver := testResolver(nil)

	if got := resolver.Name(sidAlice); got != "" {
		t.Fatalf("Name = %q, want an empty name", got)
	}
	if _, cached := resolver.cache[sidAlice]; !cached {
		t.Error("a miss must be cached, or the same SID is looked up again every cycle")
	}
}

// TestResolverUseIndexKeepsWhatItLearned checks that pointing the resolver at a newer
// reading names the principals created since the run started.
func TestResolverUseIndexKeepsWhatItLearned(t *testing.T) {
	resolver := testResolver(map[string]string{sidBob: "svc_backup"})

	resolver.UseIndex(map[string]string{sidBob: "svc_backup", sidAlice: "jdoe"})
	if got := resolver.Name(sidAlice); got != "MANTICORE.local\\jdoe" {
		t.Errorf("Name of a newly indexed SID = %q", got)
	}

	// A nil index is a reading that carried none, and must not blank the resolver.
	resolver.UseIndex(nil)
	if got := resolver.Name(sidBob); got != "MANTICORE.local\\svc_backup" {
		t.Errorf("a nil index must be ignored, got %q", got)
	}
}

// TestResolverMatches checks the --trustee matching, on the SID, on the name, and on
// a substring of either.
func TestResolverMatches(t *testing.T) {
	resolver := testResolver(map[string]string{sidBob: "svc_backup"})

	testCases := []struct {
		needle string
		want   bool
	}{
		{"", true},
		{sidBob, true},
		{"1114", true},
		{"svc_backup", true},
		{"SVC_BACKUP", true},
		{"backup", true},
		{"MANTICORE.local", true},
		{"administrator", false},
	}

	for _, testCase := range testCases {
		if got := resolver.Matches(sidBob, testCase.needle); got != testCase.want {
			t.Errorf("Matches(%s, %q) = %v, want %v", sidBob, testCase.needle, got, testCase.want)
		}
	}
}

// TestResolverMatchesAnUnnamedTrustee checks that a SID with no name is still
// matchable by its SID, and is not matched by an arbitrary name.
func TestResolverMatchesAnUnnamedTrustee(t *testing.T) {
	resolver := testResolver(nil)

	if !resolver.Matches(sidAlice, "1109") {
		t.Error("an unnamed trustee must still match on its SID")
	}
	if resolver.Matches(sidAlice, "jdoe") {
		t.Error("an unnamed trustee must not match a name")
	}
}

// TestResolverWithoutASessionNeverLooksUp checks the property diff mode relies on:
// with no session the resolver answers from what it has and never reaches out.
func TestResolverWithoutASessionNeverLooksUp(t *testing.T) {
	resolver := NewResolver(nil, "", nil, []string{"DC=MANTICORE,DC=local"})

	if got := resolver.lookup(sidAlice); got != "" {
		t.Errorf("lookup with no session = %q, want an empty name", got)
	}
	// A nil snapshot must still leave the resolver usable rather than nil-mapped.
	if got := resolver.Name(sidEveryone); got != "Everyone" {
		t.Errorf("Name over a nil snapshot = %q", got)
	}
}

// TestObjectSIDFilterEscapesTheBinarySid checks that a SID goes into a filter as the
// escape of each of its bytes, which is the only form a server matches on for a binary
// attribute.
func TestObjectSIDFilterEscapesTheBinarySid(t *testing.T) {
	filter, err := objectSIDFilter(sidEveryone)
	if err != nil {
		t.Fatalf("objectSIDFilter: %s", err)
	}

	// S-1-1-0 is revision 1, one sub-authority, authority 1, sub-authority 0.
	const want = "(objectSid=\\01\\01\\00\\00\\00\\00\\00\\01\\00\\00\\00\\00)"
	if filter != want {
		t.Errorf("filter = %q, want %q", filter, want)
	}
	if strings.Contains(filter, "S-1-") {
		t.Error("the filter must not carry the string form of the SID")
	}
}

// TestObjectSIDFilterRejectsGarbage checks that an unparseable SID is an error rather
// than a filter that would match nothing and look like a resolution failure.
func TestObjectSIDFilterRejectsGarbage(t *testing.T) {
	if _, err := objectSIDFilter("not-a-sid"); err == nil {
		t.Error("expected an unparseable SID to be refused")
	}
}

// TestSecurityDescriptorControlsAlwaysNameTheParts checks the control that every
// reading carries. Leaving the SACL in when it was not asked for makes a domain
// controller return the attribute empty for any client without SeSecurityPrivilege,
// which is the whole reason the control is sent at all.
func TestSecurityDescriptorControlsAlwaysNameTheParts(t *testing.T) {
	testCases := []struct {
		name        string
		includeSACL bool
		want        int32
	}{
		{"without the SACL", false, int32(ldap.SECURITY_INFORMATION_DEFAULT)},
		{"with the SACL", true, int32(ldap.SECURITY_INFORMATION_DEFAULT | ldap.SACL_SECURITY_INFORMATION)},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			controls := securityDescriptorControls(testCase.includeSACL)
			if len(controls) != 1 {
				t.Fatalf("expected exactly one control, got %d", len(controls))
			}

			sdFlags, ok := controls[0].(*ldap.ControlMicrosoftSDFlags)
			if !ok {
				t.Fatalf("control is %T, want *ldap.ControlMicrosoftSDFlags", controls[0])
			}
			if sdFlags.ControlValue != testCase.want {
				t.Errorf("control value = 0x%x, want 0x%x", sdFlags.ControlValue, testCase.want)
			}
			if got := sdFlags.GetControlType(); got != "1.2.840.113556.1.4.801" {
				t.Errorf("control OID = %q", got)
			}
		})
	}
}

// TestSnapshotAttributesCoverWhatTheDiffAndTheIndexNeed guards the attribute list: a
// missing descriptor makes the tool blind, and a missing objectSid or sAMAccountName
// costs every trustee its name.
func TestSnapshotAttributesCoverWhatTheDiffAndTheIndexNeed(t *testing.T) {
	required := []string{attributeSecurityDescriptor, attributeObjectSID, attributeSAMAccountName, attributeWhenChanged}
	for _, attribute := range required {
		found := false
		for _, requested := range snapshotAttributes {
			if requested == attribute {
				found = true
			}
		}
		if !found {
			t.Errorf("the reading does not ask for %q", attribute)
		}
	}
}

// TestScopeFilterFallsBackToTheDefault checks that an unset filter reads every object
// rather than sending an empty filter, which a server rejects.
func TestScopeFilterFallsBackToTheDefault(t *testing.T) {
	if got := (Scope{}).Filter(); got != DefaultLDAPFilter {
		t.Errorf("Filter() = %q, want %q", got, DefaultLDAPFilter)
	}
	if got := (Scope{LDAPFilter: "(objectClass=user)"}).Filter(); got != "(objectClass=user)" {
		t.Errorf("Filter() = %q", got)
	}
}
