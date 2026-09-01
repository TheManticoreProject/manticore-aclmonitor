package acls

import "testing"

// changeWith builds the change produced by moving one object from one descriptor to
// another, which is what every filter test starts from.
//
// Parameters:
//
//	t (*testing.T): The test.
//	beforeSDDL (string): The descriptor before.
//	afterSDDL (string): The descriptor after.
//
// Returns:
//
//	The single change.
func changeWith(t *testing.T, beforeSDDL string, afterSDDL string) Change {
	t.Helper()
	before := snapshotOf(t, map[string]string{targetDN: beforeSDDL})
	after := snapshotOf(t, map[string]string{targetDN: afterSDDL})
	return onlyChange(t, Diff(before, after, DiffOptions{}))
}

// TestFilterOnlyNotableKeepsTheAttacksAndDropsTheRest checks the filter that turns a
// noisy domain into the handful of changes worth acting on.
func TestFilterOnlyNotableKeepsTheAttacksAndDropsTheRest(t *testing.T) {
	notable := changeWith(t,
		"O:BAG:BAD:(A;;RP;;;"+sidAlice+")",
		"O:BAG:BAD:(A;;RP;;;"+sidAlice+")(OA;;CR;"+guidReplicationGetChangesAll+";;"+sidBob+")")
	ordinary := changeWith(t,
		"O:BAG:BAD:(A;;RP;;;"+sidAlice+")",
		"O:BAG:BAD:(A;;RP;;;"+sidAlice+")(A;;RC;;;"+sidBob+")")

	resolver := testResolver(nil)
	reporting := Reporting{OnlyNotable: true}

	if kept := FilterChanges([]Change{notable}, reporting, resolver); len(kept) != 1 {
		t.Errorf("a DCSync grant must survive --only-notable, got %d changes", len(kept))
	}
	if kept := FilterChanges([]Change{ordinary}, reporting, resolver); len(kept) != 0 {
		t.Errorf("a read-control grant must not survive --only-notable, got %+v", kept)
	}
}

// TestFilterOnlyNotableKeepsAnOwnerChange checks that the changes that are notable in
// themselves survive: the owner of an object can rewrite its ACL whatever the ACL
// says, so a new owner is never filtered out as ordinary.
func TestFilterOnlyNotableKeepsAnOwnerChange(t *testing.T) {
	change := changeWith(t,
		"O:BAG:BAD:(A;;RP;;;"+sidAlice+")",
		"O:"+sidBob+"G:BAD:(A;;RP;;;"+sidAlice+")")

	if kept := FilterChanges([]Change{change}, Reporting{OnlyNotable: true}, testResolver(nil)); len(kept) != 1 {
		t.Errorf("an owner change must survive --only-notable, got %d changes", len(kept))
	}
}

// TestFilterTrusteeMatchesBySidAndByName checks both ways of naming a principal.
func TestFilterTrusteeMatchesBySidAndByName(t *testing.T) {
	change := changeWith(t,
		"O:BAG:BAD:(A;;RP;;;"+sidAlice+")",
		"O:BAG:BAD:(A;;RP;;;"+sidAlice+")(A;;WP;;;"+sidBob+")")
	resolver := testResolver(map[string]string{sidBob: "svc_backup"})

	for _, needle := range []string{sidBob, "svc_backup", "SVC_BACK"} {
		kept := FilterChanges([]Change{change}, Reporting{Trustee: needle}, resolver)
		if len(kept) != 1 || len(kept[0].DACL.Added) != 1 {
			t.Errorf("--trustee %q should have kept the ACE, got %+v", needle, kept)
		}
	}

	if kept := FilterChanges([]Change{change}, Reporting{Trustee: "somebody-else"}, resolver); len(kept) != 0 {
		t.Errorf("--trustee naming another principal must drop the change, got %+v", kept)
	}
}

// TestFilterNeverHidesAParseFailure checks the one thing a display filter must not be
// able to suppress: the tool saying it could not read something.
func TestFilterNeverHidesAParseFailure(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})
	after := NewSnapshot()
	after.Objects[targetDN] = &ObjectSecurity{RawDescriptor: []byte{0x01, 0x00, 0x04, 0x80}}
	change := onlyChange(t, Diff(before, after, DiffOptions{}))

	reporting := Reporting{OnlyNotable: true, Trustee: "nobody-at-all"}
	if kept := FilterChanges([]Change{change}, reporting, testResolver(nil)); len(kept) != 1 {
		t.Errorf("a parse failure must survive every filter, got %d changes", len(kept))
	}
}

// TestFilterKeepsObjectLifecycleChanges checks the documented behaviour: an object
// appearing or disappearing carries no ACE for a filter to be applied to, so it is
// always reported rather than silently dropped.
func TestFilterKeepsObjectLifecycleChanges(t *testing.T) {
	changes := []Change{
		{Kind: DescriptorAppeared, DistinguishedName: targetDN},
		{Kind: DescriptorDisappeared, DistinguishedName: targetDN},
	}

	reporting := Reporting{OnlyNotable: true, Trustee: "nobody-at-all"}
	if kept := FilterChanges(changes, reporting, testResolver(nil)); len(kept) != 2 {
		t.Errorf("appearances and disappearances must always be reported, got %d", len(kept))
	}
}

// TestFilterWithNothingSetChangesNothing checks the cheap path.
func TestFilterWithNothingSetChangesNothing(t *testing.T) {
	change := changeWith(t,
		"O:BAG:BAD:(A;;RP;;;"+sidAlice+")",
		"O:BAG:BAD:(A;;RP;;;"+sidAlice+")(A;;RC;;;"+sidBob+")")

	if kept := FilterChanges([]Change{change}, Reporting{}, testResolver(nil)); len(kept) != 1 {
		t.Errorf("with no filter set nothing may be dropped, got %d changes", len(kept))
	}
}
