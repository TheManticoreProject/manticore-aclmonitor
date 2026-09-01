package acls

import (
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/rights"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

// firstAce parses a descriptor from SDDL and returns the first entry of its DACL,
// which is how a test names the ACE it wants to describe.
//
// Parameters:
//
//	t (*testing.T): The test.
//	sddl (string): The descriptor in SDDL.
//
// Returns:
//
//	The first ACE of the DACL.
func firstAce(t *testing.T, sddl string) *ace.AccessControlEntry {
	t.Helper()

	descriptor := &securitydescriptor.NtSecurityDescriptor{}
	if _, err := descriptor.Unmarshal(descriptorBytes(t, sddl)); err != nil {
		t.Fatalf("could not read back the fixture %q: %s", sddl, err)
	}
	if descriptor.DACL == nil || len(descriptor.DACL.Entries) == 0 {
		t.Fatalf("the fixture %q holds no ACE", sddl)
	}
	return &descriptor.DACL.Entries[0]
}

// TestDescribeAceNamesTheAttackForEveryNotablePair walks the table that is the point
// of the tool: each of these pairs has to come out as the sentence an operator can
// act on, and has to be marked notable so that --only-notable keeps it.
func TestDescribeAceNamesTheAttackForEveryNotablePair(t *testing.T) {
	testCases := []struct {
		name     string
		sddl     string
		expected string
	}{
		{"DCSync", "O:BAG:BAD:(OA;;CR;" + guidReplicationGetChangesAll + ";;" + sidBob + ")", "DCSync"},
		{"force change password", "O:BAG:BAD:(OA;;CR;" + guidForceChangePassword + ";;" + sidBob + ")", "reset the password"},
		{"shadow credentials", "O:BAG:BAD:(OA;;WP;" + guidKeyCredentialLink + ";;" + sidBob + ")", "Shadow credentials"},
		{"write member", "O:BAG:BAD:(OA;;WP;" + guidMember + ";;" + sidBob + ")", "add members to the group"},
		{"generic all", "O:BAG:BAD:(A;;GA;;;" + sidBob + ")", "Full control"},
		{"full mask", "O:BAG:BAD:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;" + sidBob + ")", "Full control"},
		{"write dacl", "O:BAG:BAD:(A;;WD;;;" + sidBob + ")", "rewrite the ACL"},
		{"write owner", "O:BAG:BAD:(A;;WO;;;" + sidBob + ")", "take ownership"},
		{"write all properties", "O:BAG:BAD:(A;;WP;;;" + sidBob + ")", "write every attribute"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			descriptions := DescribeAce(firstAce(t, testCase.sddl))
			if len(descriptions) == 0 {
				t.Fatal("expected at least one right to be described")
			}
			if !IsNotable(descriptions) {
				t.Errorf("this pair must be marked notable, got %+v", descriptions)
			}

			found := false
			for _, description := range descriptions {
				if strings.Contains(description.Text, testCase.expected) {
					found = true
				}
			}
			if !found {
				t.Errorf("expected a description holding %q, got %+v", testCase.expected, descriptions)
			}
		})
	}
}

// TestDescribeAceCollapsesFullControl checks that the thirteen bits of a full-control
// mask read as one statement rather than as a list nobody will read.
func TestDescribeAceCollapsesFullControl(t *testing.T) {
	descriptions := DescribeAce(firstAce(t, "O:BAG:BAD:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;"+sidBob+")"))
	if len(descriptions) != 1 {
		t.Fatalf("expected full control to be one line, got %d: %+v", len(descriptions), descriptions)
	}
	if descriptions[0].Text != "Full control over the object" {
		t.Errorf("got %q", descriptions[0].Text)
	}
}

// TestDescribeAceDoesNotCollapseScopedRights checks the guard on that collapsing: the
// same bits scoped to one attribute are not control of the object, and must not read
// as if they were.
func TestDescribeAceDoesNotCollapseScopedRights(t *testing.T) {
	descriptions := DescribeAce(firstAce(t, "O:BAG:BAD:(OA;;RPWPCRCCDCLCLORCWOWDSDDTSW;"+guidMember+";;"+sidBob+")"))
	for _, description := range descriptions {
		if description.Text == "Full control over the object" {
			t.Errorf("rights scoped to an attribute must not read as full control over the object: %+v", descriptions)
		}
	}
}

// TestDescribeAceFallsBackToTheWinaclName checks that a pair the table does not know
// still says something true: the name of the right, and what it is scoped to.
func TestDescribeAceFallsBackToTheWinaclName(t *testing.T) {
	// An extended right that is real but carries no entry in the notable table.
	const applyGroupPolicy = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"

	descriptions := DescribeAce(firstAce(t, "O:BAG:BAD:(OA;;CR;"+applyGroupPolicy+";;"+sidBob+")"))
	if len(descriptions) != 1 {
		t.Fatalf("expected 1 right, got %d: %+v", len(descriptions), descriptions)
	}
	if descriptions[0].Notable {
		t.Error("a pair the table does not know must not be marked notable")
	}
	if !strings.Contains(descriptions[0].Text, "DS_CONTROL_ACCESS") {
		t.Errorf("expected the right to be named, got %q", descriptions[0].Text)
	}
	if !strings.Contains(descriptions[0].Text, "EXTENDED_RIGHT_APPLY_GROUP_POLICY") {
		t.Errorf("expected the object type to be resolved by winacl, got %q", descriptions[0].Text)
	}
}

// TestDescribeMaskOfNoBits checks the empty case, which is what a re-masked ACE with
// nothing revoked hands in.
func TestDescribeMaskOfNoBits(t *testing.T) {
	if descriptions := DescribeMask(0, firstAce(t, "O:BAG:BAD:(A;;RP;;;"+sidBob+")")); len(descriptions) != 0 {
		t.Errorf("expected no description for an empty mask, got %+v", descriptions)
	}
}

// TestDescribeMaskReportsUnrecognizedBits checks that a bit no known right claims is
// shown rather than dropped.
func TestDescribeMaskReportsUnrecognizedBits(t *testing.T) {
	entry := firstAce(t, "O:BAG:BAD:(A;;RP;;;"+sidBob+")")

	descriptions := DescribeMask(rights.RIGHT_DS_READ_PROPERTY|0x00000800, entry)
	found := false
	for _, description := range descriptions {
		if strings.Contains(description.Text, "0x00000800") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the unrecognized bit to be reported, got %+v", descriptions)
	}
}

// TestAceVerb checks the word at the head of every ACE line.
func TestAceVerb(t *testing.T) {
	testCases := []struct {
		sddl string
		want string
	}{
		{"O:BAG:BAD:(A;;RP;;;" + sidBob + ")", "Allow"},
		{"O:BAG:BAD:(D;;RP;;;" + sidBob + ")", "Deny"},
		{"O:BAG:BAD:(OA;;CR;" + guidForceChangePassword + ";;" + sidBob + ")", "Allow"},
		{"O:BAG:BAD:(OD;;CR;" + guidForceChangePassword + ";;" + sidBob + ")", "Deny"},
	}

	for _, testCase := range testCases {
		if got := AceVerb(firstAce(t, testCase.sddl)); got != testCase.want {
			t.Errorf("AceVerb(%q) = %q, want %q", testCase.sddl, got, testCase.want)
		}
	}
}

// TestInheritedObjectTypeOf checks that an ACE restricted to inheriting onto one class
// says so, and that one with no such restriction says nothing.
func TestInheritedObjectTypeOf(t *testing.T) {
	const userClass = "bf967aba-0de6-11d0-a285-00aa003049e2"

	restricted := firstAce(t, "O:BAG:BAD:(OA;CI;WP;"+guidMember+";"+userClass+";"+sidBob+")")
	if got := InheritedObjectTypeOf(restricted); got == "" {
		t.Error("expected the inherited object type to be reported")
	}

	unrestricted := firstAce(t, "O:BAG:BAD:(A;;WP;;;"+sidBob+")")
	if got := InheritedObjectTypeOf(unrestricted); got != "" {
		t.Errorf("expected no inherited object type, got %q", got)
	}
}

// TestObjectRightsTableHasNoDuplicateKeys guards the table against a row being
// silently shadowed by a later one with the same right and GUID.
func TestObjectRightsTableHasNoDuplicateKeys(t *testing.T) {
	seen := map[string]string{}
	for _, entry := range objectRights {
		key := objectRightKey(entry.right, entry.guid)
		if previous, exists := seen[key]; exists {
			t.Errorf("duplicate row for right 0x%08x on %s: %q and %q", entry.right, entry.guid, previous, entry.text)
		}
		seen[key] = entry.text
	}
}
