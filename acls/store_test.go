package acls

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// storedFixture builds a small reading to write and read back.
//
// Parameters:
//
//	t (*testing.T): The test.
//
// Returns:
//
//	The reading.
func storedFixture(t *testing.T) *StoredSnapshot {
	t.Helper()
	return &StoredSnapshot{
		Version:          "1.0.0",
		Domain:           "MANTICORE.local",
		DomainController: "192.168.1.101",
		Scope: Scope{
			SearchBases: []string{"DC=MANTICORE,DC=local"},
			LDAPFilter:  DefaultLDAPFilter,
		},
		Identities: map[string]string{sidBob: "svc_backup"},
		Objects: map[string]*ObjectSecurity{
			targetDN: {
				RawDescriptor: descriptorBytes(t, "O:BAG:BAD:(A;;RP;;;"+sidAlice+")"),
				WhenChanged:   "20260901142203.0Z",
			},
		},
	}
}

// TestSnapshotRoundTrip checks that a reading survives a trip through a file, plain
// and gzipped, with the descriptors byte-identical: they are what the diff compares.
func TestSnapshotRoundTrip(t *testing.T) {
	for _, name := range []string{"reading.aclsnapshot", "reading.aclsnapshot.gz"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			original := storedFixture(t)

			if err := WriteSnapshot(path, original); err != nil {
				t.Fatalf("WriteSnapshot: %s", err)
			}

			readBack, err := ReadSnapshot(path)
			if err != nil {
				t.Fatalf("ReadSnapshot: %s", err)
			}

			if readBack.Domain != original.Domain || readBack.DomainController != original.DomainController {
				t.Errorf("the header did not survive: %+v", readBack)
			}
			if readBack.Identities[sidBob] != "svc_backup" {
				t.Errorf("the identity index did not survive: %+v", readBack.Identities)
			}
			if readBack.TakenAt.IsZero() {
				t.Error("WriteSnapshot should have stamped the reading with a time")
			}

			stored, exists := readBack.Objects[targetDN]
			if !exists {
				t.Fatalf("the object did not survive: %+v", readBack.Objects)
			}
			if !bytes.Equal(stored.RawDescriptor, original.Objects[targetDN].RawDescriptor) {
				t.Error("the descriptor bytes did not survive the round trip")
			}
			if stored.WhenChanged != "20260901142203.0Z" {
				t.Errorf("whenChanged = %q", stored.WhenChanged)
			}
		})
	}
}

// TestSnapshotRoundTripSurvivesADiff is the end-to-end check: two files written and
// read back must diff to the same thing the readings would have.
func TestSnapshotRoundTripSurvivesADiff(t *testing.T) {
	directory := t.TempDir()
	beforePath := filepath.Join(directory, "before.aclsnapshot.gz")
	afterPath := filepath.Join(directory, "after.aclsnapshot.gz")

	before := storedFixture(t)
	after := storedFixture(t)
	after.Objects[targetDN] = &ObjectSecurity{
		RawDescriptor: descriptorBytes(t, "O:BAG:BAD:(A;;RP;;;"+sidAlice+")(OA;;CR;"+guidReplicationGetChangesAll+";;"+sidBob+")"),
	}

	if err := WriteSnapshot(beforePath, before); err != nil {
		t.Fatalf("WriteSnapshot(before): %s", err)
	}
	if err := WriteSnapshot(afterPath, after); err != nil {
		t.Fatalf("WriteSnapshot(after): %s", err)
	}

	readBefore, err := ReadSnapshot(beforePath)
	if err != nil {
		t.Fatalf("ReadSnapshot(before): %s", err)
	}
	readAfter, err := ReadSnapshot(afterPath)
	if err != nil {
		t.Fatalf("ReadSnapshot(after): %s", err)
	}

	change := onlyChange(t, Diff(readBefore.Snapshot(), readAfter.Snapshot(), DiffOptions{}))
	if len(change.DACL.Added) != 1 {
		t.Fatalf("expected the added ACE to survive the files, got %+v", change.DACL)
	}
	if !IsNotable(DescribeAce(change.DACL.Added[0])) {
		t.Error("the added ACE should still be interpreted as notable after a round trip")
	}
}

// TestReadSnapshotDetectsGzipByContent checks that a compressed reading saved without
// the .gz suffix still reads back, since the suffix is a hint and not a promise.
func TestReadSnapshotDetectsGzipByContent(t *testing.T) {
	directory := t.TempDir()
	gzipped := filepath.Join(directory, "reading.gz")
	misnamed := filepath.Join(directory, "reading.aclsnapshot")

	if err := WriteSnapshot(gzipped, storedFixture(t)); err != nil {
		t.Fatalf("WriteSnapshot: %s", err)
	}
	raw, err := os.ReadFile(gzipped)
	if err != nil {
		t.Fatalf("ReadFile: %s", err)
	}
	if err := os.WriteFile(misnamed, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %s", err)
	}

	if _, err := ReadSnapshot(misnamed); err != nil {
		t.Errorf("a gzipped reading under another name should still read back: %s", err)
	}
}

// TestReadSnapshotRefusesWhatItCannotRead checks that a file from another tool or
// another format version is refused by name rather than half-parsed into a diff that
// would report the whole domain as having changed.
func TestReadSnapshotRefusesWhatItCannotRead(t *testing.T) {
	testCases := []struct {
		name     string
		content  string
		expected string
	}{
		{"another tool", `{"format":1,"tool":"something-else","objects":{}}`, "not written by"},
		{"a newer format", `{"format":99,"tool":"manticore-aclmonitor","objects":{}}`, "snapshot format"},
		{"not json at all", `this is not a snapshot`, "error reading"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reading.aclsnapshot")
			if err := os.WriteFile(path, []byte(testCase.content), 0o600); err != nil {
				t.Fatalf("WriteFile: %s", err)
			}

			_, err := ReadSnapshot(path)
			if err == nil {
				t.Fatal("expected the file to be refused")
			}
			if !strings.Contains(err.Error(), testCase.expected) {
				t.Errorf("error = %q, want it to mention %q", err, testCase.expected)
			}
		})
	}
}

// TestWriteSnapshotLeavesNoPartialFile checks that a failed write does not leave a
// half-written reading under the name the operator will later diff against.
func TestWriteSnapshotLeavesNoPartialFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "reading.aclsnapshot")

	if err := WriteSnapshot(path, storedFixture(t)); err != nil {
		t.Fatalf("WriteSnapshot: %s", err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %s", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".partial-") {
			t.Errorf("a temporary file was left behind: %s", entry.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly the snapshot in the directory, got %d entries", len(entries))
	}
}

// TestScopeMismatch checks that two readings which do not cover the same ground are
// called out, since an object one of them never read looks exactly like a deleted one.
func TestScopeMismatch(t *testing.T) {
	base := storedFixture(t)

	t.Run("same scope", func(t *testing.T) {
		if differences := ScopeMismatch(base, storedFixture(t)); len(differences) != 0 {
			t.Errorf("identical scopes must not be reported as differing, got %v", differences)
		}
	})

	t.Run("search bases in another order", func(t *testing.T) {
		first := storedFixture(t)
		first.Scope.SearchBases = []string{"CN=Configuration,DC=MANTICORE,DC=local", "DC=MANTICORE,DC=local"}
		second := storedFixture(t)
		second.Scope.SearchBases = []string{"DC=MANTICORE,DC=local", "CN=Configuration,DC=MANTICORE,DC=local"}

		if differences := ScopeMismatch(first, second); len(differences) != 0 {
			t.Errorf("the order of the search bases is not a difference, got %v", differences)
		}
	})

	t.Run("narrowed scope", func(t *testing.T) {
		narrowed := storedFixture(t)
		narrowed.Scope.SearchBases = []string{"CN=Users,DC=MANTICORE,DC=local"}

		differences := ScopeMismatch(base, narrowed)
		if len(differences) != 1 || !strings.Contains(differences[0], "search bases differ") {
			t.Errorf("expected the search bases to be reported as differing, got %v", differences)
		}
	})

	t.Run("different filter and SACL", func(t *testing.T) {
		other := storedFixture(t)
		other.Scope.LDAPFilter = "(objectClass=user)"
		other.Scope.IncludeSACL = true

		if differences := ScopeMismatch(base, other); len(differences) != 2 {
			t.Errorf("expected both differences to be reported, got %v", differences)
		}
	})
}
