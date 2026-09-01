package acls

import (
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

// The SIDs the fixtures use. They are shaped like real domain SIDs so that they are
// not mistaken for well-known ones, which resolve by a different path.
const (
	sidAlice    = "S-1-5-21-1004336348-1177238915-682003330-1109"
	sidBob      = "S-1-5-21-1004336348-1177238915-682003330-1114"
	sidEveryone = "S-1-1-0"
)

// The object type GUIDs the fixtures use, as they appear in SDDL.
const (
	guidReplicationGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	guidForceChangePassword      = "00299570-246d-11d0-a768-00aa006e0529"
	guidKeyCredentialLink        = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
	guidMember                   = "bf9679c0-0de6-11d0-a285-00aa003049e2"
)

// descriptorBytes builds the wire form of a security descriptor from its SDDL, which
// is what a fixture is written as: one readable line instead of a byte blob.
//
// Parameters:
//
//	t (*testing.T): The test, failed when the SDDL cannot be parsed or serialized.
//	sddl (string): The descriptor in SDDL.
//
// Returns:
//
//	The marshalled descriptor.
func descriptorBytes(t *testing.T, sddl string) []byte {
	t.Helper()

	descriptor := &securitydescriptor.NtSecurityDescriptor{}
	if _, err := descriptor.FromSDDLString(sddl); err != nil {
		t.Fatalf("could not parse the fixture SDDL %q: %s", sddl, err)
	}

	marshalled, err := descriptor.Marshal()
	if err != nil {
		t.Fatalf("could not marshal the fixture SDDL %q: %s", sddl, err)
	}
	return marshalled
}

// snapshotOf builds a reading holding one object per given SDDL, keyed by
// distinguished name.
//
// Parameters:
//
//	t (*testing.T): The test.
//	objects (map[string]string): Distinguished name to descriptor SDDL.
//
// Returns:
//
//	The reading.
func snapshotOf(t *testing.T, objects map[string]string) *Snapshot {
	t.Helper()

	snapshot := NewSnapshot()
	for distinguishedName, sddl := range objects {
		snapshot.Objects[distinguishedName] = &ObjectSecurity{RawDescriptor: descriptorBytes(t, sddl)}
	}
	return snapshot
}

// testResolver builds a resolver over a fixed identity index and no session, which is
// what every test uses: a lookup must never reach for a domain controller.
//
// Parameters:
//
//	identities (map[string]string): SID to sAMAccountName.
//
// Returns:
//
//	The resolver.
func testResolver(identities map[string]string) *Resolver {
	snapshot := NewSnapshot()
	snapshot.Identities = identities
	return NewResolver(snapshot, "MANTICORE.local", nil, nil)
}

// onlyChange returns the single change a diff produced, failing the test when there
// is not exactly one.
//
// Parameters:
//
//	t (*testing.T): The test.
//	changes ([]Change): The changes to check.
//
// Returns:
//
//	The only change.
func onlyChange(t *testing.T, changes []Change) Change {
	t.Helper()
	if len(changes) != 1 {
		t.Fatalf("expected exactly 1 change, got %d: %+v", len(changes), changes)
	}
	return changes[0]
}
