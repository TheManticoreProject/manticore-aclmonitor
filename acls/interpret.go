package acls

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/object/flags"
	"github.com/TheManticoreProject/winacl/rights"
	"github.com/TheManticoreProject/winacl/schema"
)

// fullControlMask is every object-specific and standard right an Active Directory
// object has, which is what a domain controller writes when it is asked for full
// control. An ACE carrying it says the same thing as one carrying GENERIC_ALL, and it
// is what an ACL editor actually stores, so both have to be recognised.
const fullControlMask uint32 = rights.RIGHT_DS_CREATE_CHILD |
	rights.RIGHT_DS_DELETE_CHILD |
	rights.RIGHT_DS_LIST_CONTENTS |
	rights.RIGHT_DS_WRITE_PROPERTY_EXTENDED |
	rights.RIGHT_DS_READ_PROPERTY |
	rights.RIGHT_DS_WRITE_PROPERTY |
	rights.RIGHT_DS_DELETE_TREE |
	rights.RIGHT_DS_LIST_OBJECT |
	rights.RIGHT_DS_CONTROL_ACCESS |
	rights.RIGHT_DELETE |
	rights.RIGHT_READ_CONTROL |
	rights.RIGHT_WRITE_DAC |
	rights.RIGHT_WRITE_OWNER

// RightDescription is one right an ACE carries, in the terms an operator thinks in.
// Notable marks the ones that are worth stopping on: the rights that hand somebody
// control of the object or of the identity behind it.
type RightDescription struct {
	Text    string
	Notable bool
}

// bareRight is how one right reads when the ACE names no object type, so the right
// applies to the whole object rather than to one attribute or one extended right.
type bareRight struct {
	text    string
	notable bool
}

// bareRights covers the rights that mean something on their own. A right that is not
// here falls back to its name from winacl, which is the honest rendering for the ones
// that have no shorter English form.
var bareRights = map[uint32]bareRight{
	rights.RIGHT_GENERIC_ALL:                {"Full control over the object", true},
	rights.RIGHT_WRITE_DAC:                  {"Can rewrite the ACL of the object (WriteDacl)", true},
	rights.RIGHT_WRITE_OWNER:                {"Can take ownership of the object (WriteOwner)", true},
	rights.RIGHT_DS_WRITE_PROPERTY:          {"Can write every attribute of the object", true},
	rights.RIGHT_DS_WRITE_PROPERTY_EXTENDED: {"Can perform every validated write on the object", true},
	rights.RIGHT_DS_CONTROL_ACCESS:          {"Holds every extended right on the object", true},
	rights.RIGHT_DELETE:                     {"Can delete the object", false},
	rights.RIGHT_DS_DELETE_TREE:             {"Can delete the object and everything under it", false},
	rights.RIGHT_DS_CREATE_CHILD:            {"Can create child objects of any class", false},
	rights.RIGHT_DS_DELETE_CHILD:            {"Can delete child objects of any class", false},
	rights.RIGHT_DS_READ_PROPERTY:           {"Can read every attribute of the object", false},
	rights.RIGHT_READ_CONTROL:               {"Can read the ACL of the object", false},
}

// objectRight is how one right reads when the ACE names the object type it applies
// to: an extended right, a property set, or a single attribute.
type objectRight struct {
	right   uint32
	guid    string
	text    string
	notable bool
}

// objectRights is the table that turns a (right, object type) pair into the attack it
// enables. Everything in it is a way to take over the object or the identity behind
// it, so every row is notable; a pair that is not here falls back to the name winacl
// resolves the GUID to, which is still readable, just not interpreted.
var objectRights = []objectRight{
	{rights.RIGHT_DS_CONTROL_ACCESS, rights.EXTENDED_RIGHT_USER_FORCE_CHANGE_PASSWORD,
		"Can reset the password of this account without knowing the current one (ForceChangePassword)", true},
	{rights.RIGHT_DS_CONTROL_ACCESS, rights.EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES,
		"Half of DCSync (DS-Replication-Get-Changes)", true},
	{rights.RIGHT_DS_CONTROL_ACCESS, rights.EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_ALL,
		"DCSync: can replicate secrets out of the domain (DS-Replication-Get-Changes-All)", true},
	{rights.RIGHT_DS_CONTROL_ACCESS, rights.EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET,
		"Can replicate the filtered attribute set (DS-Replication-Get-Changes-In-Filtered-Set)", true},
	{rights.RIGHT_DS_CONTROL_ACCESS, rights.EXTENDED_RIGHT_CERTIFICATE_ENROLLMENT,
		"Can enroll for certificates against this template (Certificate-Enrollment)", true},
	{rights.RIGHT_DS_CONTROL_ACCESS, rights.EXTENDED_RIGHT_DS_CLONE_DOMAIN_CONTROLLER,
		"Can clone a domain controller (DS-Clone-Domain-Controller)", true},

	{rights.RIGHT_DS_WRITE_PROPERTY, schema.SCHEMA_ATTRIBUTE_MEMBER,
		"Can add members to the group, itself included", true},
	{rights.RIGHT_DS_WRITE_PROPERTY_EXTENDED, schema.SCHEMA_ATTRIBUTE_MEMBER,
		"Can add and remove itself from the group (Self-Membership)", true},
	{rights.RIGHT_DS_WRITE_PROPERTY, schema.SCHEMA_ATTRIBUTE_MS_DS_KEY_CREDENTIAL_LINK,
		"Shadow credentials: can add a key credential and authenticate as this account", true},
	{rights.RIGHT_DS_WRITE_PROPERTY, schema.SCHEMA_ATTRIBUTE_MS_DS_ALLOWED_TO_ACT_ON_BEHALF_OF_OTHER_IDENTITY,
		"Resource-based constrained delegation: can let another account impersonate anyone to this one", true},
	{rights.RIGHT_DS_WRITE_PROPERTY, schema.SCHEMA_ATTRIBUTE_SERVICE_PRINCIPAL_NAME,
		"Targeted kerberoasting: can give this account an SPN and request a ticket for it", true},
	{rights.RIGHT_DS_WRITE_PROPERTY, schema.SCHEMA_ATTRIBUTE_MS_DS_ALLOWED_TO_DELEGATE_TO,
		"Can set constrained delegation on this account", true},
	{rights.RIGHT_DS_WRITE_PROPERTY, schema.SCHEMA_ATTRIBUTE_SCRIPT_PATH,
		"Can point the logon script of this account at a file it controls", true},
	{rights.RIGHT_DS_WRITE_PROPERTY, schema.SCHEMA_ATTRIBUTE_USER_ACCOUNT_CONTROL,
		"Can rewrite the account control flags of this account", true},
}

// objectRightIndex is objectRights keyed for lookup, built once.
var objectRightIndex = buildObjectRightIndex()

// buildObjectRightIndex keys the object rights table by right and lower-cased GUID.
//
// Returns:
//
//	The lookup table.
func buildObjectRightIndex() map[string]RightDescription {
	index := make(map[string]RightDescription, len(objectRights))
	for _, entry := range objectRights {
		index[objectRightKey(entry.right, entry.guid)] = RightDescription{Text: entry.text, Notable: entry.notable}
	}
	return index
}

// objectRightKey builds the lookup key of a (right, object type GUID) pair.
//
// Parameters:
//
//	right (uint32): The access mask bit.
//	objectTypeGUID (string): The object type GUID in format D.
//
// Returns:
//
//	The key.
func objectRightKey(right uint32, objectTypeGUID string) string {
	return fmt.Sprintf("%08x|%s", right, strings.ToLower(objectTypeGUID))
}

// DescribeAce renders the rights an ACE carries.
//
// Parameters:
//
//	entry (*ace.AccessControlEntry): The entry to describe.
//
// Returns:
//
//	One description per right the entry carries, in a stable order.
func DescribeAce(entry *ace.AccessControlEntry) []RightDescription {
	return DescribeMask(entry.Mask.RawValue, entry)
}

// DescribeMask renders a set of access mask bits in the context of the ACE that
// carries them, which is what says whether a right applies to the whole object or to
// one attribute of it.
//
// It is called with a mask that is not the ACE's own when a right was granted or
// revoked on an existing entry: the bits that moved are described, in the context of
// the entry they moved on.
//
// Parameters:
//
//	rawMask (uint32): The access mask bits to describe.
//	entry (*ace.AccessControlEntry): The entry the bits belong to, which supplies the
//	  object type they apply to.
//
// Returns:
//
//	One description per right in the mask, in a stable order. A mask with no bit set
//	yields an empty slice.
func DescribeMask(rawMask uint32, entry *ace.AccessControlEntry) []RightDescription {
	if rawMask == 0 {
		return []RightDescription{}
	}

	objectTypeGUID, objectTypeName := objectTypeOf(entry)

	// Full control is one statement, not thirteen. It is only collapsed when the ACE
	// applies to the whole object: the same bits scoped to one attribute are not
	// control of the object and must not read as if they were.
	if objectTypeGUID == "" && (rawMask&rights.RIGHT_GENERIC_ALL == rights.RIGHT_GENERIC_ALL || rawMask&fullControlMask == fullControlMask) {
		descriptions := []RightDescription{{Text: "Full control over the object", Notable: true}}
		return append(descriptions, describeRights(rawMask&^(fullControlMask|rights.RIGHT_GENERIC_ALL), "", "")...)
	}

	return describeRights(rawMask, objectTypeGUID, objectTypeName)
}

// describeRights renders every bit of a mask.
//
// Parameters:
//
//	rawMask (uint32): The access mask bits to describe.
//	objectTypeGUID (string): The object type the rights apply to, empty for the whole object.
//	objectTypeName (string): The readable name of that object type.
//
// Returns:
//
//	One description per right in the mask, ordered by mask bit so that the same set of
//	rights always reads the same way.
func describeRights(rawMask uint32, objectTypeGUID string, objectTypeName string) []RightDescription {
	descriptions := []RightDescription{}
	for _, right := range sortedRightValues() {
		if rawMask&right != right {
			continue
		}
		descriptions = append(descriptions, describeRight(right, objectTypeGUID, objectTypeName))
	}

	// A bit that no known right claims is still a bit that was set. Showing it as hex
	// beats dropping it silently.
	if unknown := rawMask &^ knownRightsMask(); unknown != 0 {
		descriptions = append(descriptions, RightDescription{Text: fmt.Sprintf("Unrecognized access mask bits 0x%08x", unknown)})
	}

	return descriptions
}

// describeRight renders one right.
//
// Parameters:
//
//	right (uint32): The access mask bit.
//	objectTypeGUID (string): The object type the right applies to, empty for the whole object.
//	objectTypeName (string): The readable name of that object type.
//
// Returns:
//
//	The description.
func describeRight(right uint32, objectTypeGUID string, objectTypeName string) RightDescription {
	if objectTypeGUID != "" {
		if description, exists := objectRightIndex[objectRightKey(right, objectTypeGUID)]; exists {
			return description
		}
		// Not a pair the table knows: name the right and what it is scoped to, which
		// winacl already resolves to an extended right, a property set or an attribute.
		return RightDescription{Text: fmt.Sprintf("%s on %s", rightName(right), objectTypeName)}
	}

	if description, exists := bareRights[right]; exists {
		return RightDescription{Text: description.text, Notable: description.notable}
	}

	return RightDescription{Text: rightName(right)}
}

// objectTypeOf returns the object type an ACE is scoped to.
//
// Parameters:
//
//	entry (*ace.AccessControlEntry): The entry to read.
//
// Returns:
//
//	The object type GUID in format D and its readable name, both empty when the entry
//	applies to the whole object.
func objectTypeOf(entry *ace.AccessControlEntry) (string, string) {
	if entry == nil {
		return "", ""
	}
	if entry.AccessControlObjectType.Flags.Value&flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT == 0 {
		return "", ""
	}

	objectTypeGUID := entry.AccessControlObjectType.ObjectType.GUID.ToFormatD()
	name := entry.AccessControlObjectType.ObjectType.GUID.LookupName()
	if name == "?" {
		name = objectTypeGUID
	}
	return objectTypeGUID, name
}

// InheritedObjectTypeOf returns the class an ACE is restricted to inheriting onto, if
// any.
//
// Parameters:
//
//	entry (*ace.AccessControlEntry): The entry to read.
//
// Returns:
//
//	The readable name of the inherited object type, empty when the entry names none.
func InheritedObjectTypeOf(entry *ace.AccessControlEntry) string {
	if entry == nil {
		return ""
	}
	if entry.AccessControlObjectType.Flags.Value&flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT == 0 {
		return ""
	}

	name := entry.AccessControlObjectType.InheritedObjectType.GUID.LookupName()
	if name == "?" {
		return entry.AccessControlObjectType.InheritedObjectType.GUID.ToFormatD()
	}
	// An inherited object type is always an object class, never an attribute, but
	// winacl resolves any GUID it recognises through the schema attribute table and
	// labels it as one. The label would read as "LDAP Attribute: user objects", so it
	// is dropped here and the class name kept.
	return strings.TrimPrefix(name, "LDAP Attribute: ")
}

// AceVerb is how the type of an ACE reads at the head of a line: what the entry does
// to the trustee it names.
//
// Parameters:
//
//	entry (*ace.AccessControlEntry): The entry to read.
//
// Returns:
//
//	"Allow", "Deny", "Audit", or the raw type name for the types that are none of the
//	three.
func AceVerb(entry *ace.AccessControlEntry) string {
	switch entry.Header.Type.Value {
	case acetype.ACE_TYPE_ACCESS_ALLOWED,
		acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT,
		acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
		acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		return "Allow"
	case acetype.ACE_TYPE_ACCESS_DENIED,
		acetype.ACE_TYPE_ACCESS_DENIED_OBJECT,
		acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK,
		acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:
		return "Deny"
	case acetype.ACE_TYPE_SYSTEM_AUDIT,
		acetype.ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		acetype.ACE_TYPE_SYSTEM_AUDIT_CALLBACK,
		acetype.ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		return "Audit"
	}
	return entry.Header.Type.String()
}

// IsNotable reports whether any of the given descriptions is one worth stopping on.
//
// Parameters:
//
//	descriptions ([]RightDescription): The descriptions to check.
//
// Returns:
//
//	True when at least one is notable.
func IsNotable(descriptions []RightDescription) bool {
	for _, description := range descriptions {
		if description.Notable {
			return true
		}
	}
	return false
}

// rightName returns the winacl name of a right, or its hex value when it has none.
//
// Parameters:
//
//	right (uint32): The access mask bit.
//
// Returns:
//
//	The name.
func rightName(right uint32) string {
	if name, exists := rights.RightValueToRightName[right]; exists {
		return name
	}
	return fmt.Sprintf("0x%08x", right)
}

// sortedRightValues returns the known access mask bits in ascending order, so that a
// set of rights is always listed in the same order.
//
// Returns:
//
//	The right values, sorted.
func sortedRightValues() []uint32 {
	values := make([]uint32, 0, len(rights.RightValueToRightName))
	for value := range rights.RightValueToRightName {
		values = append(values, value)
	}
	sort.Slice(values, func(i int, j int) bool { return values[i] < values[j] })
	return values
}

// knownRightsMask is every bit that has a name, so that the ones that do not can be
// reported rather than dropped.
var knownRights = func() uint32 {
	var mask uint32
	for value := range rights.RightValueToRightName {
		mask |= value
	}
	return mask
}()

// knownRightsMask returns the union of every named access mask bit.
//
// Returns:
//
//	The mask.
func knownRightsMask() uint32 {
	return knownRights
}
