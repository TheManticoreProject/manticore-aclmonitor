package acls

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/aceflags"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

// ChangeKind tells what happened to the security descriptor of an object between two
// readings.
type ChangeKind int

const (
	// DescriptorAppeared is an object whose descriptor is in the new reading only.
	// That is an object that was created, and equally an object whose descriptor the
	// bound account could not read before and can now.
	DescriptorAppeared ChangeKind = iota
	// DescriptorDisappeared is an object whose descriptor is in the old reading only:
	// the object was deleted, or its descriptor stopped being readable.
	DescriptorDisappeared
	// DescriptorChanged is an object present in both readings whose descriptor moved.
	DescriptorChanged
)

// ACLKind names which of the two access control lists a change happened in.
type ACLKind int

const (
	// DACL is the discretionary access control list, which grants and denies access.
	DACL ACLKind = iota
	// SACL is the system access control list, which says what is audited.
	SACL
)

// String returns the name of the access control list.
//
// Returns:
//
//	"DACL" or "SACL".
func (kind ACLKind) String() string {
	if kind == SACL {
		return "SACL"
	}
	return "DACL"
}

// IdentityChange is an owner or a group that moved from one SID to another. Either
// side is empty when the descriptor did not carry one.
type IdentityChange struct {
	Before string
	After  string
}

// FlagsChange is the control field of a descriptor moving. Set and Cleared hold the
// names of the flags that were turned on and off.
type FlagsChange struct {
	Before  uint16
	After   uint16
	Set     []string
	Cleared []string
}

// AceMaskChange is one ACE that stayed in the list, against the same trustee and with
// the same type, flags and object types, whose access mask moved. Granted and Revoked
// are the bits that were added and taken away.
type AceMaskChange struct {
	Before  *ace.AccessControlEntry
	After   *ace.AccessControlEntry
	Granted uint32
	Revoked uint32
}

// ACLChanges is everything that happened inside one access control list.
type ACLChanges struct {
	Added   []*ace.AccessControlEntry
	Removed []*ace.AccessControlEntry
	Changed []AceMaskChange
	// Presence is set when the list itself appeared, disappeared or went empty,
	// which is a different statement from any ACE moving. Empty otherwise.
	Presence string
}

// IsEmpty reports whether nothing happened in the list.
//
// Returns:
//
//	True when there is nothing to report, false otherwise.
func (changes ACLChanges) IsEmpty() bool {
	return len(changes.Added) == 0 && len(changes.Removed) == 0 && len(changes.Changed) == 0 && changes.Presence == ""
}

// Change is everything that happened to the security descriptor of one object.
type Change struct {
	Kind              ChangeKind
	DistinguishedName string
	// WhenChanged is the directory's own timestamp of the last write to the object,
	// as it stands in the newer of the two readings.
	WhenChanged string

	Owner        *IdentityChange
	Group        *IdentityChange
	ControlFlags *FlagsChange
	DACL         ACLChanges
	SACL         ACLChanges

	// Before and After are the parsed descriptors, kept so that a mode asked for the
	// SDDL can render it without parsing them a second time. Before is nil for an
	// object that appeared, After is nil for one that disappeared.
	Before *securitydescriptor.NtSecurityDescriptor
	After  *securitydescriptor.NtSecurityDescriptor

	// ParseError is set when a descriptor could not be unmarshalled. The change is
	// still reported, since the bytes did move, but nothing could be said about how.
	ParseError error
}

// HasDetail reports whether anything was found inside a changed descriptor.
//
// A descriptor whose bytes moved but that yields no reportable detail is real: a
// re-serialization with the same content, or a change that a filter dropped. Such a
// change is not printed.
//
// Returns:
//
//	True when there is something to show below the object line.
func (change Change) HasDetail() bool {
	return change.Owner != nil || change.Group != nil || change.ControlFlags != nil ||
		!change.DACL.IsEmpty() || !change.SACL.IsEmpty() || change.ParseError != nil
}

// DiffOptions says how much of a descriptor to compare.
type DiffOptions struct {
	// IgnoreInherited drops the ACEs a domain controller wrote onto this object
	// because they were set higher up the tree. One write to a container lands on
	// every object below it, so a run that is looking for the write itself asks for
	// this and sees the cause instead of the storm.
	IgnoreInherited bool
	// IncludeSACL compares the system access control list as well. It is only ever
	// populated when the reading asked the server for it.
	IncludeSACL bool
}

// Diff compares two readings and returns every change between them.
//
// The result is grouped by kind, appearances first, then disappearances, then
// changes, and each group is sorted by distinguished name, so that the output of a
// cycle is reproducible: ranging over a map would report the same set of changes in a
// different order every time.
//
// Parameters:
//
//	before (*Snapshot): The state of the descriptors at the previous reading.
//	after (*Snapshot): The state of the descriptors at the latest reading.
//	options (DiffOptions): How much of a descriptor to compare.
//
// Returns:
//
//	Every change between the two readings.
func Diff(before *Snapshot, after *Snapshot, options DiffOptions) []Change {
	changes := []Change{}

	for _, distinguishedName := range sortedKeys(after.Objects) {
		if _, exists := before.Objects[distinguishedName]; !exists {
			changes = append(changes, Change{
				Kind:              DescriptorAppeared,
				DistinguishedName: distinguishedName,
				WhenChanged:       after.Objects[distinguishedName].WhenChanged,
			})
		}
	}

	for _, distinguishedName := range sortedKeys(before.Objects) {
		if _, exists := after.Objects[distinguishedName]; !exists {
			changes = append(changes, Change{
				Kind:              DescriptorDisappeared,
				DistinguishedName: distinguishedName,
			})
		}
	}

	for _, distinguishedName := range sortedKeys(after.Objects) {
		previous, exists := before.Objects[distinguishedName]
		if !exists {
			continue
		}
		current := after.Objects[distinguishedName]

		// The whole point of holding the descriptors as bytes: a quiet object costs
		// one comparison, not two unmarshals.
		if bytes.Equal(previous.RawDescriptor, current.RawDescriptor) {
			continue
		}

		change := diffDescriptors(distinguishedName, previous, current, options)
		if change.HasDetail() {
			changes = append(changes, change)
		}
	}

	return changes
}

// diffDescriptors compares the two descriptors of one object.
//
// Parameters:
//
//	distinguishedName (string): The distinguished name of the object.
//	before (*ObjectSecurity): The descriptor at the previous reading.
//	after (*ObjectSecurity): The descriptor at the latest reading.
//	options (DiffOptions): How much of a descriptor to compare.
//
// Returns:
//
//	The change, which carries a ParseError when either descriptor could not be read.
func diffDescriptors(distinguishedName string, before *ObjectSecurity, after *ObjectSecurity, options DiffOptions) Change {
	change := Change{
		Kind:              DescriptorChanged,
		DistinguishedName: distinguishedName,
		WhenChanged:       after.WhenChanged,
	}

	previousDescriptor, err := parseDescriptor(before.RawDescriptor)
	if err != nil {
		change.ParseError = fmt.Errorf("the previous descriptor could not be read: %w", err)
		return change
	}
	currentDescriptor, err := parseDescriptor(after.RawDescriptor)
	if err != nil {
		change.ParseError = fmt.Errorf("the new descriptor could not be read: %w", err)
		return change
	}

	change.Before = previousDescriptor
	change.After = currentDescriptor

	change.Owner = diffIdentity(ownerSID(previousDescriptor), ownerSID(currentDescriptor))
	change.Group = diffIdentity(groupSID(previousDescriptor), groupSID(currentDescriptor))
	change.ControlFlags = diffControlFlags(previousDescriptor.Header.Control, currentDescriptor.Header.Control)

	change.DACL = diffDACL(previousDescriptor, currentDescriptor, options)
	if options.IncludeSACL {
		change.SACL = diffSACL(previousDescriptor, currentDescriptor, options)
	}

	return change
}

// parseDescriptor unmarshals a security descriptor.
//
// Parameters:
//
//	rawDescriptor ([]byte): The bytes of the descriptor as the server returned them.
//
// Returns:
//
//	The parsed descriptor, or an error if it could not be read.
func parseDescriptor(rawDescriptor []byte) (*securitydescriptor.NtSecurityDescriptor, error) {
	descriptor := &securitydescriptor.NtSecurityDescriptor{}
	if _, err := descriptor.Unmarshal(rawDescriptor); err != nil {
		return nil, err
	}
	return descriptor, nil
}

// ownerSID returns the string form of the owner SID of a descriptor, or an empty
// string when it carries none.
//
// Parameters:
//
//	descriptor (*securitydescriptor.NtSecurityDescriptor): The descriptor to read.
//
// Returns:
//
//	The owner SID, or an empty string.
func ownerSID(descriptor *securitydescriptor.NtSecurityDescriptor) string {
	if descriptor.Owner == nil {
		return ""
	}
	return descriptor.Owner.SID.ToString()
}

// groupSID returns the string form of the group SID of a descriptor, or an empty
// string when it carries none.
//
// Parameters:
//
//	descriptor (*securitydescriptor.NtSecurityDescriptor): The descriptor to read.
//
// Returns:
//
//	The group SID, or an empty string.
func groupSID(descriptor *securitydescriptor.NtSecurityDescriptor) string {
	if descriptor.Group == nil {
		return ""
	}
	return descriptor.Group.SID.ToString()
}

// diffIdentity compares an owner or a group between two descriptors.
//
// Parameters:
//
//	before (string): The SID at the previous reading, empty when there was none.
//	after (string): The SID at the latest reading, empty when there is none.
//
// Returns:
//
//	The change, or nil when the identity did not move.
func diffIdentity(before string, after string) *IdentityChange {
	if before == after {
		return nil
	}
	return &IdentityChange{Before: before, After: after}
}

// diffControlFlags compares the control field of two descriptors.
//
// This is where breaking inheritance shows up: SE_DACL_PROTECTED turning on is a
// domain controller being told to stop applying the ACEs of the parent to this
// object, which no ACE of its own records.
//
// Parameters:
//
//	before (control.NtSecurityDescriptorControl): The control field at the previous reading.
//	after (control.NtSecurityDescriptorControl): The control field at the latest reading.
//
// Returns:
//
//	The change, or nil when no flag moved.
func diffControlFlags(before control.NtSecurityDescriptorControl, after control.NtSecurityDescriptorControl) *FlagsChange {
	if before.RawValue == after.RawValue {
		return nil
	}

	change := &FlagsChange{Before: before.RawValue, After: after.RawValue}
	for _, flag := range sortedFlagValues() {
		wasSet := before.RawValue&flag == flag
		isSet := after.RawValue&flag == flag
		switch {
		case !wasSet && isSet:
			change.Set = append(change.Set, control.NtSecurityDescriptorControlValueToName[flag])
		case wasSet && !isSet:
			change.Cleared = append(change.Cleared, control.NtSecurityDescriptorControlValueToName[flag])
		}
	}

	return change
}

// sortedFlagValues returns the control flag bit masks in ascending order, so that the
// flags of a change are always listed in the same order.
//
// Returns:
//
//	The control flag values, sorted.
func sortedFlagValues() []uint16 {
	values := make([]uint16, 0, len(control.NtSecurityDescriptorControlValueToName))
	for value := range control.NtSecurityDescriptorControlValueToName {
		values = append(values, value)
	}
	sort.Slice(values, func(i int, j int) bool { return values[i] < values[j] })
	return values
}

// diffDACL compares the discretionary access control lists of two descriptors.
//
// Parameters:
//
//	before (*securitydescriptor.NtSecurityDescriptor): The descriptor at the previous reading.
//	after (*securitydescriptor.NtSecurityDescriptor): The descriptor at the latest reading.
//	options (DiffOptions): How much of a descriptor to compare.
//
// Returns:
//
//	Everything that happened in the list.
func diffDACL(before *securitydescriptor.NtSecurityDescriptor, after *securitydescriptor.NtSecurityDescriptor, options DiffOptions) ACLChanges {
	previousPresent, currentPresent := before.DACL != nil, after.DACL != nil

	var previousEntries, currentEntries []ace.AccessControlEntry
	if previousPresent {
		previousEntries = before.DACL.Entries
	}
	if currentPresent {
		currentEntries = after.DACL.Entries
	}

	changes := diffEntries(previousEntries, currentEntries, options.IgnoreInherited)
	changes.Presence = describePresence(DACL, previousPresent, currentPresent, len(previousEntries), len(currentEntries))
	return changes
}

// diffSACL compares the system access control lists of two descriptors.
//
// Parameters:
//
//	before (*securitydescriptor.NtSecurityDescriptor): The descriptor at the previous reading.
//	after (*securitydescriptor.NtSecurityDescriptor): The descriptor at the latest reading.
//	options (DiffOptions): How much of a descriptor to compare.
//
// Returns:
//
//	Everything that happened in the list.
func diffSACL(before *securitydescriptor.NtSecurityDescriptor, after *securitydescriptor.NtSecurityDescriptor, options DiffOptions) ACLChanges {
	previousPresent, currentPresent := before.SACL != nil, after.SACL != nil

	var previousEntries, currentEntries []ace.AccessControlEntry
	if previousPresent {
		previousEntries = before.SACL.Entries
	}
	if currentPresent {
		currentEntries = after.SACL.Entries
	}

	changes := diffEntries(previousEntries, currentEntries, options.IgnoreInherited)
	changes.Presence = describePresence(SACL, previousPresent, currentPresent, len(previousEntries), len(currentEntries))
	return changes
}

// describePresence names an access control list appearing, disappearing or going
// empty.
//
// An absent DACL and an empty one are opposites, and saying which one happened is the
// whole content of the change: a descriptor with no DACL grants everyone full
// control, and one with a DACL holding no ACE denies everyone everything.
//
// Parameters:
//
//	kind (ACLKind): Which list this is.
//	wasPresent (bool): Whether the list was there at the previous reading.
//	isPresent (bool): Whether the list is there at the latest reading.
//	entriesBefore (int): How many entries it held before.
//	entriesAfter (int): How many entries it holds now.
//
// Returns:
//
//	The sentence to report, or an empty string when the presence did not change.
func describePresence(kind ACLKind, wasPresent bool, isPresent bool, entriesBefore int, entriesAfter int) string {
	switch {
	case wasPresent && !isPresent:
		if kind == DACL {
			return "The DACL was removed: with no DACL, everyone is granted full control of the object"
		}
		return "The SACL was removed: nothing about the object is audited any more"
	case !wasPresent && isPresent:
		return fmt.Sprintf("A %s was added, holding %d entries", kind, entriesAfter)
	case wasPresent && isPresent && entriesBefore > 0 && entriesAfter == 0:
		if kind == DACL {
			return "The DACL was emptied: an empty DACL denies everyone every access to the object"
		}
		return "The SACL was emptied: nothing about the object is audited any more"
	}
	return ""
}

// diffEntries matches the ACEs of two access control lists.
//
// An ACE carries no identifier, so "the same ACE with a different mask" has to be
// inferred. It happens in two passes. The first compares the two lists as multisets
// of complete ACEs, which finds what was added and what was removed and handles a
// list holding the same ACE twice. The second pairs a removed with an added ACE that
// agree on everything but their mask, which is what a right being granted or revoked
// on an existing entry looks like on the wire.
//
// Parameters:
//
//	before ([]ace.AccessControlEntry): The entries at the previous reading.
//	after ([]ace.AccessControlEntry): The entries at the latest reading.
//	ignoreInherited (bool): Whether to drop the entries that were inherited.
//
// Returns:
//
//	The entries added, removed and re-masked.
func diffEntries(before []ace.AccessControlEntry, after []ace.AccessControlEntry, ignoreInherited bool) ACLChanges {
	previousEntries := selectEntries(before, ignoreInherited)
	currentEntries := selectEntries(after, ignoreInherited)

	removed := leftover(previousEntries, currentEntries)
	added := leftover(currentEntries, previousEntries)

	// Pair what is left by identity: same type, same flags, same object types, same
	// trustee, different mask.
	removedByIdentity := map[string][]*ace.AccessControlEntry{}
	for _, entry := range removed {
		key := aceIdentityKey(entry)
		removedByIdentity[key] = append(removedByIdentity[key], entry)
	}

	changes := ACLChanges{}
	stillAdded := []*ace.AccessControlEntry{}
	paired := map[*ace.AccessControlEntry]bool{}

	for _, entry := range added {
		key := aceIdentityKey(entry)
		candidates := removedByIdentity[key]
		if len(candidates) == 0 {
			stillAdded = append(stillAdded, entry)
			continue
		}

		counterpart := candidates[0]
		removedByIdentity[key] = candidates[1:]
		paired[counterpart] = true

		changes.Changed = append(changes.Changed, AceMaskChange{
			Before:  counterpart,
			After:   entry,
			Granted: entry.Mask.RawValue &^ counterpart.Mask.RawValue,
			Revoked: counterpart.Mask.RawValue &^ entry.Mask.RawValue,
		})
	}

	changes.Added = stillAdded
	for _, entry := range removed {
		if !paired[entry] {
			changes.Removed = append(changes.Removed, entry)
		}
	}

	return changes
}

// selectEntries returns pointers to the entries to compare, dropping the inherited
// ones when the caller asked for that.
//
// Parameters:
//
//	entries ([]ace.AccessControlEntry): The entries of an access control list.
//	ignoreInherited (bool): Whether to drop the entries that were inherited.
//
// Returns:
//
//	Pointers into the given slice, in order.
func selectEntries(entries []ace.AccessControlEntry, ignoreInherited bool) []*ace.AccessControlEntry {
	selected := make([]*ace.AccessControlEntry, 0, len(entries))
	for index := range entries {
		entry := &entries[index]
		if ignoreInherited && entry.HasFlag(aceflags.ACE_FLAG_INHERITED) {
			continue
		}
		selected = append(selected, entry)
	}
	return selected
}

// leftover returns the entries of one list that the other does not account for,
// comparing the two as multisets of complete ACEs.
//
// Parameters:
//
//	entries ([]*ace.AccessControlEntry): The list to take the leftovers of.
//	other ([]*ace.AccessControlEntry): The list to account against.
//
// Returns:
//
//	The entries of the first list that have no counterpart in the second, in order.
func leftover(entries []*ace.AccessControlEntry, other []*ace.AccessControlEntry) []*ace.AccessControlEntry {
	available := map[string]int{}
	for _, entry := range other {
		available[aceFingerprint(entry)]++
	}

	remaining := []*ace.AccessControlEntry{}
	for _, entry := range entries {
		fingerprint := aceFingerprint(entry)
		if available[fingerprint] > 0 {
			available[fingerprint]--
			continue
		}
		remaining = append(remaining, entry)
	}
	return remaining
}

// aceIdentityKey identifies an ACE by everything except the rights it carries, so
// that the same entry with a different access mask matches itself across two
// readings.
//
// Parameters:
//
//	entry (*ace.AccessControlEntry): The entry to key.
//
// Returns:
//
//	The key.
func aceIdentityKey(entry *ace.AccessControlEntry) string {
	return fmt.Sprintf(
		"%02x|%02x|%08x|%s|%s|%s|%s",
		entry.Header.Type.Value,
		entry.Header.Flags.RawValue,
		entry.AccessControlObjectType.Flags.Value,
		entry.AccessControlObjectType.ObjectType.GUID.ToFormatD(),
		entry.AccessControlObjectType.InheritedObjectType.GUID.ToFormatD(),
		entry.Identity.SID.ToString(),
		hex.EncodeToString(entry.ApplicationData.RawBytes),
	)
}

// aceFingerprint identifies an ACE completely, mask included.
//
// Parameters:
//
//	entry (*ace.AccessControlEntry): The entry to fingerprint.
//
// Returns:
//
//	The fingerprint.
func aceFingerprint(entry *ace.AccessControlEntry) string {
	return fmt.Sprintf("%s|%08x", aceIdentityKey(entry), entry.Mask.RawValue)
}

// sortedKeys returns the distinguished names of a reading in ascending order.
//
// Parameters:
//
//	objects (map[string]*ObjectSecurity): The objects to read the distinguished names of.
//
// Returns:
//
//	The distinguished names, sorted.
func sortedKeys(objects map[string]*ObjectSecurity) []string {
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
