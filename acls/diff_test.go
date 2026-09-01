package acls

import (
	"fmt"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/rights"
)

const targetDN = "CN=Administrator,CN=Users,DC=MANTICORE,DC=local"

// TestDiffReportsAppearanceAndDisappearance checks the two object-level changes.
func TestDiffReportsAppearanceAndDisappearance(t *testing.T) {
	before := snapshotOf(t, map[string]string{
		"CN=Gone,DC=MANTICORE,DC=local": "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")",
	})
	after := snapshotOf(t, map[string]string{
		"CN=New,DC=MANTICORE,DC=local": "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")",
	})

	changes := Diff(before, after, DiffOptions{})
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(changes))
	}
	if changes[0].Kind != DescriptorAppeared || changes[0].DistinguishedName != "CN=New,DC=MANTICORE,DC=local" {
		t.Errorf("first change should be the appearance of CN=New, got %+v", changes[0])
	}
	if changes[1].Kind != DescriptorDisappeared || changes[1].DistinguishedName != "CN=Gone,DC=MANTICORE,DC=local" {
		t.Errorf("second change should be the disappearance of CN=Gone, got %+v", changes[1])
	}
}

// TestDiffIgnoresAnUnchangedDescriptor checks the fast path: identical bytes are never
// parsed and never reported.
func TestDiffIgnoresAnUnchangedDescriptor(t *testing.T) {
	sddl := "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"
	before := snapshotOf(t, map[string]string{targetDN: sddl})
	after := snapshotOf(t, map[string]string{targetDN: sddl})

	if changes := Diff(before, after, DiffOptions{}); len(changes) != 0 {
		t.Errorf("expected no change, got %+v", changes)
	}
}

// TestDiffReportsAnAddedAce checks that a new ACE is reported as added and not as a
// pair of unrelated edits.
func TestDiffReportsAnAddedAce(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")(OA;;CR;" + guidReplicationGetChangesAll + ";;" + sidBob + ")"})

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if change.Kind != DescriptorChanged {
		t.Fatalf("expected a changed descriptor, got kind %d", change.Kind)
	}
	if len(change.DACL.Added) != 1 {
		t.Fatalf("expected 1 added ACE, got %d (removed %d, changed %d)", len(change.DACL.Added), len(change.DACL.Removed), len(change.DACL.Changed))
	}
	if got := change.DACL.Added[0].Identity.SID.ToString(); got != sidBob {
		t.Errorf("added ACE trustee = %s, want %s", got, sidBob)
	}
	if len(change.DACL.Removed) != 0 || len(change.DACL.Changed) != 0 {
		t.Errorf("nothing should have been removed or re-masked, got %d removed and %d changed", len(change.DACL.Removed), len(change.DACL.Changed))
	}
}

// TestDiffReportsARemovedAce checks the mirror case.
func TestDiffReportsARemovedAce(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")(A;;WP;;;" + sidBob + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if len(change.DACL.Removed) != 1 {
		t.Fatalf("expected 1 removed ACE, got %d", len(change.DACL.Removed))
	}
	if got := change.DACL.Removed[0].Identity.SID.ToString(); got != sidBob {
		t.Errorf("removed ACE trustee = %s, want %s", got, sidBob)
	}
}

// TestDiffPairsAReMaskedAce is the case the two-pass matching exists for: the same
// entry, against the same trustee, with rights added and taken away. It must read as
// one change, not as a removal plus an addition.
func TestDiffPairsAReMaskedAce(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidBob + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;WDWO;;;" + sidBob + ")"})

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if len(change.DACL.Changed) != 1 {
		t.Fatalf("expected 1 re-masked ACE, got %d (added %d, removed %d)", len(change.DACL.Changed), len(change.DACL.Added), len(change.DACL.Removed))
	}
	if len(change.DACL.Added) != 0 || len(change.DACL.Removed) != 0 {
		t.Errorf("a re-masked ACE must not also be reported as added or removed")
	}

	maskChange := change.DACL.Changed[0]
	wantGranted := rights.RIGHT_WRITE_DAC | rights.RIGHT_WRITE_OWNER
	if maskChange.Granted != wantGranted {
		t.Errorf("granted = 0x%08x, want 0x%08x", maskChange.Granted, wantGranted)
	}
	if maskChange.Revoked != rights.RIGHT_DS_READ_PROPERTY {
		t.Errorf("revoked = 0x%08x, want 0x%08x", maskChange.Revoked, rights.RIGHT_DS_READ_PROPERTY)
	}
}

// TestDiffDoesNotPairAcesOfDifferentTrustees checks that the pairing pass keys on the
// trustee: a right moving from one principal to another is two changes, not one.
func TestDiffDoesNotPairAcesOfDifferentTrustees(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;WP;;;" + sidAlice + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;WP;;;" + sidBob + ")"})

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if len(change.DACL.Changed) != 0 {
		t.Errorf("ACEs of different trustees must not be paired, got %d re-masked", len(change.DACL.Changed))
	}
	if len(change.DACL.Added) != 1 || len(change.DACL.Removed) != 1 {
		t.Errorf("expected 1 added and 1 removed, got %d and %d", len(change.DACL.Added), len(change.DACL.Removed))
	}
}

// TestDiffDoesNotPairAcesOfDifferentObjectTypes checks that the pairing pass keys on
// the object type too: the same right scoped to a different attribute is a different
// entry, and reading it as a re-mask would report an empty granted and revoked set.
func TestDiffDoesNotPairAcesOfDifferentObjectTypes(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(OA;;WP;" + guidMember + ";;" + sidBob + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(OA;;WP;" + guidKeyCredentialLink + ";;" + sidBob + ")"})

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if len(change.DACL.Changed) != 0 {
		t.Errorf("ACEs scoped to different attributes must not be paired, got %d re-masked", len(change.DACL.Changed))
	}
	if len(change.DACL.Added) != 1 || len(change.DACL.Removed) != 1 {
		t.Errorf("expected 1 added and 1 removed, got %d and %d", len(change.DACL.Added), len(change.DACL.Removed))
	}
}

// TestDiffHandlesDuplicateAces is why the first pass compares multisets rather than
// sets: a descriptor holding the same ACE twice and losing one copy has lost one copy,
// not none.
func TestDiffHandlesDuplicateAces(t *testing.T) {
	duplicate := "(A;;RP;;;" + sidAlice + ")"
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:" + duplicate + duplicate + duplicate})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:" + duplicate + duplicate})

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if len(change.DACL.Removed) != 1 {
		t.Errorf("expected exactly 1 removed ACE, got %d", len(change.DACL.Removed))
	}
	if len(change.DACL.Added) != 0 || len(change.DACL.Changed) != 0 {
		t.Errorf("nothing should have been added or re-masked, got %d and %d", len(change.DACL.Added), len(change.DACL.Changed))
	}
}

// TestDiffReportsAnOwnerChange checks the owner, which no ACE records.
func TestDiffReportsAnOwnerChange(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:" + sidBob + "G:BAD:(A;;RP;;;" + sidAlice + ")"})

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if change.Owner == nil {
		t.Fatal("expected an owner change")
	}
	if change.Owner.After != sidBob {
		t.Errorf("new owner = %s, want %s", change.Owner.After, sidBob)
	}
	if !change.DACL.IsEmpty() {
		t.Errorf("the DACL did not move, it must not be reported: %+v", change.DACL)
	}
}

// TestDiffReportsInheritanceBeingBroken checks the control flag that says a domain
// controller has stopped applying the parent's ACEs to this object.
func TestDiffReportsInheritanceBeingBroken(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:AI(A;;RP;;;" + sidAlice + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:PAI(A;;RP;;;" + sidAlice + ")"})

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if change.ControlFlags == nil {
		t.Fatal("expected a control flags change")
	}
	found := false
	for _, flag := range change.ControlFlags.Set {
		if flag == "DACL Protected" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'DACL Protected' among the flags set, got %v", change.ControlFlags.Set)
	}
}

// TestDiffDistinguishesAnEmptyDaclFromAnAbsentOne checks the pair that are opposites:
// no DACL grants everyone full control, an empty DACL denies everyone everything.
func TestDiffDistinguishesAnEmptyDaclFromAnAbsentOne(t *testing.T) {
	populated := "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"

	t.Run("emptied", func(t *testing.T) {
		before := snapshotOf(t, map[string]string{targetDN: populated})
		after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:"})

		change := onlyChange(t, Diff(before, after, DiffOptions{}))
		if change.DACL.Presence == "" {
			t.Fatal("expected the DACL going empty to be reported")
		}
		if !strings.Contains(change.DACL.Presence, "denies everyone") {
			t.Errorf("an emptied DACL must say it denies everyone, got %q", change.DACL.Presence)
		}
	})

	t.Run("removed", func(t *testing.T) {
		before := snapshotOf(t, map[string]string{targetDN: populated})
		after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BA"})

		change := onlyChange(t, Diff(before, after, DiffOptions{}))
		if change.DACL.Presence == "" {
			t.Fatal("expected the DACL being removed to be reported")
		}
		if !strings.Contains(change.DACL.Presence, "full control") {
			t.Errorf("a removed DACL must say it grants everyone full control, got %q", change.DACL.Presence)
		}
	})
}

// TestDiffIgnoreInheritedDropsInheritedAces checks the option that shows the write
// instead of the storm it produced below it.
func TestDiffIgnoreInheritedDropsInheritedAces(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")(A;ID;WP;;;" + sidBob + ")"})

	if change := onlyChange(t, Diff(before, after, DiffOptions{})); len(change.DACL.Added) != 1 {
		t.Fatalf("without the option the inherited ACE is reported: expected 1 added, got %d", len(change.DACL.Added))
	}

	if changes := Diff(before, after, DiffOptions{IgnoreInherited: true}); len(changes) != 0 {
		t.Errorf("with the option an inherited-only change must not be reported, got %+v", changes)
	}
}

// TestDiffReportsAnUnparseableDescriptor checks that a descriptor the library cannot
// read is still reported, since the bytes did move, and that it does not end the run.
func TestDiffReportsAnUnparseableDescriptor(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})
	after := NewSnapshot()
	after.Objects[targetDN] = &ObjectSecurity{RawDescriptor: []byte{0x01, 0x00, 0x04, 0x80}}

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if change.ParseError == nil {
		t.Fatal("expected a parse error to be carried on the change")
	}
	if !change.HasDetail() {
		t.Error("a change carrying a parse error must still be reported")
	}
}

// TestDiffSkipsTheSaclUnlessAsked checks that the SACL is only compared when the
// reading actually asked the server for it.
func TestDiffSkipsTheSaclUnlessAsked(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAS:(AU;SA;WP;;;" + sidEveryone + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAS:(AU;SA;WPRP;;;" + sidEveryone + ")"})

	if changes := Diff(before, after, DiffOptions{}); len(changes) != 0 {
		t.Errorf("without IncludeSACL the SACL must not be compared, got %+v", changes)
	}

	change := onlyChange(t, Diff(before, after, DiffOptions{IncludeSACL: true}))
	if change.SACL.IsEmpty() {
		t.Errorf("with IncludeSACL the SACL change must be reported, got %+v", change)
	}
}

// TestDiffIsOrderedAndReproducible checks that a diff of several objects comes out in
// the same order every time, since ranging over a map would not.
func TestDiffIsOrderedAndReproducible(t *testing.T) {
	before := NewSnapshot()
	after := NewSnapshot()
	for index := 0; index < 20; index++ {
		distinguishedName := fmt.Sprintf("CN=obj%02d,DC=MANTICORE,DC=local", index)
		after.Objects[distinguishedName] = &ObjectSecurity{RawDescriptor: descriptorBytes(t, "O:BAG:BAD:(A;;RP;;;"+sidAlice+")")}
	}

	first := Diff(before, after, DiffOptions{})
	for attempt := 0; attempt < 5; attempt++ {
		again := Diff(before, after, DiffOptions{})
		for index := range first {
			if first[index].DistinguishedName != again[index].DistinguishedName {
				t.Fatalf("the order of the changes is not stable: %q then %q at index %d",
					first[index].DistinguishedName, again[index].DistinguishedName, index)
			}
		}
	}
}
