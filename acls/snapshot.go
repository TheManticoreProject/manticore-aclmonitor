// Package acls holds the machinery every mode of the tool shares: reading the
// security descriptor of every object in scope, storing a reading in a file,
// resolving the trustees of an ACE to names, comparing two readings, and rendering
// the differences.
//
// The package is named acls rather than acl because winacl already exports an acl
// package, and the two are imported side by side here.
package acls

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/winacl/sid"
	goldapv3 "github.com/go-ldap/ldap/v3"
)

// DefaultLDAPFilter matches every object of a search base, the same way the
// directory itself enumerates them.
//
// It is deliberately not a presence filter on nTSecurityDescriptor: an object whose
// descriptor the bound account cannot read comes back with the attribute absent
// rather than being filtered out server-side, and TakeSnapshot skips it. Filtering on
// the attribute instead would make an unreadable object and a non-existent one
// indistinguishable.
const DefaultLDAPFilter = "(objectClass=*)"

// Attribute names read for every object. The descriptor is the point; the SID and the
// sAMAccountName build the identity index for free, since the enumeration is already
// walking every object; whenChanged carries the directory's own timestamp of the last
// write, which is what a change can be correlated against in a domain controller's
// event log.
const (
	attributeSecurityDescriptor = "nTSecurityDescriptor"
	attributeObjectSID          = "objectSid"
	attributeSAMAccountName     = "sAMAccountName"
	attributeWhenChanged        = "whenChanged"
)

// snapshotAttributes is the attribute list every read asks for.
var snapshotAttributes = []string{
	attributeSecurityDescriptor,
	attributeObjectSID,
	attributeSAMAccountName,
	attributeWhenChanged,
}

// Scope is what to read: where, which objects, and how much of each descriptor.
type Scope struct {
	// SearchBases are the distinguished names to enumerate, each as a whole subtree.
	SearchBases []string `json:"searchBases"`
	// LDAPFilter restricts which objects are read. Empty means DefaultLDAPFilter.
	LDAPFilter string `json:"ldapFilter"`
	// IncludeSACL asks the server for the system access control list as well.
	IncludeSACL bool `json:"includeSacl"`
}

// Filter returns the LDAP filter of the scope, falling back to the default.
//
// Returns:
//
//	The filter to send.
func (scope Scope) Filter() string {
	if scope.LDAPFilter == "" {
		return DefaultLDAPFilter
	}
	return scope.LDAPFilter
}

// ObjectSecurity is the security descriptor of one object at one point in time.
//
// The descriptor is held as the bytes the server returned and is not parsed here.
// Two readings are compared by comparing those bytes, and only the objects whose
// bytes moved are ever unmarshalled: a domain with thousands of objects would
// otherwise pay a full parse of every descriptor, every cycle, to report nothing.
type ObjectSecurity struct {
	RawDescriptor []byte `json:"sd"`
	WhenChanged   string `json:"whenChanged,omitempty"`
}

// Snapshot is the security descriptor of every object in scope at one point in time,
// together with the identity index built while reading them.
type Snapshot struct {
	// Objects maps a distinguished name to the security descriptor of that object.
	Objects map[string]*ObjectSecurity `json:"objects"`
	// Identities maps the string form of a SID to the sAMAccountName of the object
	// that holds it, for every object that was read. It is what lets an ACE name its
	// trustee without a lookup, and it travels with a stored snapshot so that a diff
	// run offline can still name them.
	Identities map[string]string `json:"identities"`
}

// NewSnapshot returns an empty snapshot.
//
// Returns:
//
//	A snapshot with both of its maps allocated.
func NewSnapshot() *Snapshot {
	return &Snapshot{
		Objects:    make(map[string]*ObjectSecurity),
		Identities: make(map[string]string),
	}
}

// TakeSnapshot reads the security descriptor of every object of every search base.
//
// Parameters:
//
//	ldapSession (*ldap.Session): The connected LDAP session to query.
//	scope (Scope): What to read: the search bases, the filter, and whether to ask for
//	  the SACL.
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	The security descriptor of every object found, or an error if a search failed.
func TakeSnapshot(ldapSession *ldap.Session, scope Scope, debug bool) (*Snapshot, error) {
	snapshot := NewSnapshot()
	controls := securityDescriptorControls(scope.IncludeSACL)
	filter := scope.Filter()

	for _, searchBase := range scope.SearchBases {
		entries, err := ldapSession.QueryWholeSubtreeWithControls(searchBase, filter, snapshotAttributes, controls)
		if err != nil {
			return nil, fmt.Errorf("error querying search base '%s': %w", searchBase, err)
		}

		if debug {
			logger.Debug(fmt.Sprintf("Search base '%s' returned %d objects", searchBase, len(entries)))
		}

		unreadable := 0
		for _, entry := range entries {
			// A distinguished name is unique in the directory, so two search bases
			// returning the same one means they overlap: the second copy is the same
			// object and is skipped rather than diffed against itself.
			if _, exists := snapshot.Objects[entry.DN]; exists {
				if debug {
					logger.Debug(fmt.Sprintf("Object '%s' already in the snapshot, search bases overlap", entry.DN))
				}
				continue
			}

			snapshot.indexIdentity(entry)

			descriptor := entry.GetEqualFoldRawAttributeValue(attributeSecurityDescriptor)
			if len(descriptor) == 0 {
				// The bound account cannot read this object's descriptor. It is not
				// in the snapshot, so it is not diffed, and it is not reported as
				// having disappeared either. Counted so the run can say how much of
				// the directory it is blind to.
				unreadable++
				continue
			}

			snapshot.Objects[entry.DN] = &ObjectSecurity{
				RawDescriptor: descriptor,
				WhenChanged:   entry.GetEqualFoldAttributeValue(attributeWhenChanged),
			}
		}

		if unreadable > 0 && debug {
			logger.Debug(fmt.Sprintf("Search base '%s': %d objects returned no readable security descriptor", searchBase, unreadable))
		}
	}

	return snapshot, nil
}

// indexIdentity records the SID and the sAMAccountName of an entry, so that an ACE
// naming that SID as its trustee can be rendered with a name.
//
// Parameters:
//
//	entry (*ldap.Entry): The entry to read the identity of.
func (snapshot *Snapshot) indexIdentity(entry *ldap.Entry) {
	accountName := entry.GetEqualFoldAttributeValue(attributeSAMAccountName)
	if accountName == "" {
		return
	}

	rawSID := entry.GetEqualFoldRawAttributeValue(attributeObjectSID)
	if len(rawSID) == 0 {
		return
	}

	securityIdentifier := sid.SID{}
	if _, err := securityIdentifier.Unmarshal(rawSID); err != nil {
		// An unparseable objectSid costs a name in the output and nothing else, so it
		// is not worth failing the snapshot over.
		return
	}

	snapshot.Identities[securityIdentifier.ToString()] = accountName
}

// securityDescriptorControls builds the LDAP controls a security descriptor read has
// to carry.
//
// Reading nTSecurityDescriptor without LDAP_SERVER_SD_FLAGS_OID makes a domain
// controller try to include the SACL, and a client that does not hold
// SE_SECURITY_NAME then gets the attribute back absent from the entry, with no error
// at all. So the parts to return are always named explicitly, and the SACL is only
// among them when the caller asked for it.
//
// Parameters:
//
//	includeSACL (bool): Whether to ask for the system access control list.
//
// Returns:
//
//	The controls to attach to the search request.
func securityDescriptorControls(includeSACL bool) []goldapv3.Control {
	securityInformation := ldap.SECURITY_INFORMATION_DEFAULT
	if includeSACL {
		securityInformation |= ldap.SACL_SECURITY_INFORMATION
	}

	return []goldapv3.Control{
		&ldap.ControlMicrosoftSDFlags{
			Criticality:  false,
			ControlValue: int32(securityInformation),
		},
	}
}
