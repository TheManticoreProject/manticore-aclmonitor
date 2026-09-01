package acls

// Reporting is what the operator asked to be shown out of everything that changed.
//
// These are display filters, not diff options: what they drop is real and did happen.
// They apply to the contents of a changed descriptor only. An object whose descriptor
// appeared or disappeared is always reported, whatever the filters say, because such
// a change carries no ACE for a filter to be applied to and losing it silently would
// be worse than the noise.
type Reporting struct {
	// OnlyNotable keeps only the changes that move one of the rights the
	// interpretation table marks as notable, plus the ones that are notable in
	// themselves: a new owner, and inheritance being broken.
	OnlyNotable bool
	// Trustee keeps only the ACEs whose trustee matches this SID, name or substring.
	// Empty matches everything.
	Trustee string
}

// IsActive reports whether any filter is set.
//
// Returns:
//
//	True when at least one filter would drop something.
func (reporting Reporting) IsActive() bool {
	return reporting.OnlyNotable || reporting.Trustee != ""
}

// FilterChanges drops what the operator asked not to see.
//
// Parameters:
//
//	changes ([]Change): The changes to filter.
//	reporting (Reporting): What to keep.
//	resolver (*Resolver): The resolver, used to match a trustee by name.
//
// Returns:
//
//	The changes that survived, with the filtered-out entries removed from each. A
//	change left with nothing to show is dropped entirely.
func FilterChanges(changes []Change, reporting Reporting, resolver *Resolver) []Change {
	if !reporting.IsActive() {
		return changes
	}

	kept := []Change{}
	for _, change := range changes {
		if change.Kind != DescriptorChanged {
			kept = append(kept, change)
			continue
		}

		filtered := filterChange(change, reporting, resolver)
		if filtered.HasDetail() {
			kept = append(kept, filtered)
		}
	}

	return kept
}

// filterChange applies the filters to one changed descriptor.
//
// Parameters:
//
//	change (Change): The change to filter.
//	reporting (Reporting): What to keep.
//	resolver (*Resolver): The resolver, used to match a trustee by name.
//
// Returns:
//
//	The change with the filtered-out parts removed.
func filterChange(change Change, reporting Reporting, resolver *Resolver) Change {
	// A parse failure is never filtered out: it is the tool saying it could not read
	// something, which no display filter should be able to hide.
	if change.ParseError != nil {
		return change
	}

	change.Owner = filterIdentityChange(change.Owner, reporting, resolver)
	change.Group = filterIdentityChange(change.Group, reporting, resolver)

	// Naming a trustee is asking about that trustee's access, and the control flags
	// are not about any trustee, so they go. Asking for the notable changes keeps
	// them: breaking inheritance is exactly such a change.
	if reporting.Trustee != "" {
		change.ControlFlags = nil
	}

	change.DACL = filterACLChanges(change.DACL, reporting, resolver)
	change.SACL = filterACLChanges(change.SACL, reporting, resolver)

	return change
}

// filterIdentityChange keeps an owner or group change only when it survives the
// filters.
//
// An owner change is always notable: the owner of an object can rewrite its ACL
// whatever the ACL says.
//
// Parameters:
//
//	identityChange (*IdentityChange): The change to filter, may be nil.
//	reporting (Reporting): What to keep.
//	resolver (*Resolver): The resolver, used to match a trustee by name.
//
// Returns:
//
//	The change, or nil when it was filtered out.
func filterIdentityChange(identityChange *IdentityChange, reporting Reporting, resolver *Resolver) *IdentityChange {
	if identityChange == nil {
		return nil
	}

	if reporting.Trustee != "" {
		matchesBefore := identityChange.Before != "" && resolver.Matches(identityChange.Before, reporting.Trustee)
		matchesAfter := identityChange.After != "" && resolver.Matches(identityChange.After, reporting.Trustee)
		if !matchesBefore && !matchesAfter {
			return nil
		}
	}

	return identityChange
}

// filterACLChanges keeps the entries of one access control list that survive the
// filters.
//
// Parameters:
//
//	changes (ACLChanges): What moved in the list.
//	reporting (Reporting): What to keep.
//	resolver (*Resolver): The resolver, used to match a trustee by name.
//
// Returns:
//
//	The entries that survived.
func filterACLChanges(changes ACLChanges, reporting Reporting, resolver *Resolver) ACLChanges {
	filtered := ACLChanges{}

	// The list itself appearing, disappearing or going empty is not about one
	// trustee, so naming one drops it; it is notable on its own account.
	if changes.Presence != "" && reporting.Trustee == "" {
		filtered.Presence = changes.Presence
	}

	for _, entry := range changes.Added {
		if !resolver.Matches(entry.Identity.SID.ToString(), reporting.Trustee) {
			continue
		}
		if reporting.OnlyNotable && !IsNotable(DescribeAce(entry)) {
			continue
		}
		filtered.Added = append(filtered.Added, entry)
	}

	for _, entry := range changes.Removed {
		if !resolver.Matches(entry.Identity.SID.ToString(), reporting.Trustee) {
			continue
		}
		if reporting.OnlyNotable && !IsNotable(DescribeAce(entry)) {
			continue
		}
		filtered.Removed = append(filtered.Removed, entry)
	}

	for _, maskChange := range changes.Changed {
		if !resolver.Matches(maskChange.After.Identity.SID.ToString(), reporting.Trustee) {
			continue
		}
		if reporting.OnlyNotable {
			granted := DescribeMask(maskChange.Granted, maskChange.After)
			revoked := DescribeMask(maskChange.Revoked, maskChange.Before)
			if !IsNotable(granted) && !IsNotable(revoked) {
				continue
			}
		}
		filtered.Changed = append(filtered.Changed, maskChange)
	}

	return filtered
}
