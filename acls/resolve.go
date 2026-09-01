package acls

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/winacl/sid"
)

// unresolvable is what the cache holds for a SID that was looked up and not found. It
// is a distinct entry rather than an absent one so that the same SID is not looked up
// again on every cycle for the lifetime of the run.
const unresolvable = ""

// Resolver turns the SID of a trustee into a name to show the operator.
//
// It answers from the cheapest source that has an answer: the well-known SIDs that
// need no lookup at all, then the index the snapshot built while enumerating the
// directory, then the directory itself. The last of those is the only one that costs
// a round trip, and it happens for a trustee that lives outside the monitored scope:
// a principal of another domain, or a security principal that no longer exists.
//
// A Resolver with no session still answers from the first two sources, which is what
// makes diff mode work with no domain controller in reach.
type Resolver struct {
	// domain labels the names that came out of the directory, so a trustee reads as
	// MANTICORE.local\jdoe rather than as a bare jdoe. It is whatever the operator
	// named on the command line, and it is empty for a snapshot that did not record
	// one, in which case names are shown unqualified.
	domain string
	// index maps a SID to a sAMAccountName, built by the snapshot.
	index map[string]string
	// session is the directory to fall back to, or nil when offline.
	session *ldap.Session
	// searchBases are the naming contexts to look a SID up in.
	searchBases []string
	// cache holds every answer the fallback produced, including its misses.
	cache map[string]string
}

// NewResolver builds a resolver over the identity index of a snapshot.
//
// Parameters:
//
//	snapshot (*Snapshot): The snapshot whose identity index to answer from.
//	domain (string): The domain to qualify resolved names with, may be empty.
//	ldapSession (*ldap.Session): The session to look unknown SIDs up in, or nil to
//	  answer only from the index and the well-known SIDs.
//	searchBases ([]string): The naming contexts to look a SID up in.
//
// Returns:
//
//	The resolver.
func NewResolver(snapshot *Snapshot, domain string, ldapSession *ldap.Session, searchBases []string) *Resolver {
	index := map[string]string{}
	if snapshot != nil && snapshot.Identities != nil {
		index = snapshot.Identities
	}

	return &Resolver{
		domain:      domain,
		index:       index,
		session:     ldapSession,
		searchBases: searchBases,
		cache:       make(map[string]string),
	}
}

// Name returns the name of the identity behind a SID, or an empty string when it
// could not be named.
//
// Parameters:
//
//	securityIdentifier (string): The string form of the SID, as in S-1-5-21-...-1109.
//
// Returns:
//
//	The name to show, or an empty string when the SID could not be resolved.
func (resolver *Resolver) Name(securityIdentifier string) string {
	// A well-known SID names itself the same way in every domain, and its name is
	// already qualified ("BUILTIN\Administrators", "NT AUTHORITY\SYSTEM"), so it is
	// never given the domain prefix.
	if name, exists := sid.WellKnownSIDs[securityIdentifier]; exists {
		return name
	}

	if accountName, exists := resolver.index[securityIdentifier]; exists {
		return resolver.qualify(accountName)
	}

	if cached, exists := resolver.cache[securityIdentifier]; exists {
		return cached
	}

	accountName := resolver.lookup(securityIdentifier)
	if accountName == "" {
		resolver.cache[securityIdentifier] = unresolvable
		return unresolvable
	}

	qualified := resolver.qualify(accountName)
	resolver.cache[securityIdentifier] = qualified
	return qualified
}

// Display renders a SID the way it is shown in every change: the name when there is
// one, with the SID after it, and the SID on its own when there is not.
//
// The SID is always shown, even next to a name. A name is what the operator reads,
// but the SID is what the ACE actually holds, and it is what a follow-up query has to
// be written against.
//
// Parameters:
//
//	securityIdentifier (string): The string form of the SID.
//
// Returns:
//
//	The rendered identity.
func (resolver *Resolver) Display(securityIdentifier string) string {
	name := resolver.Name(securityIdentifier)
	if name == "" {
		return FormatText(securityIdentifier)
	}
	return fmt.Sprintf("%s (%s)", FormatText(name), FormatText(securityIdentifier))
}

// Matches reports whether a SID is the one the operator asked to filter on, either by
// SID or by any part of its name.
//
// Parameters:
//
//	securityIdentifier (string): The string form of the SID.
//	needle (string): The SID, name or substring to match, case-insensitively.
//
// Returns:
//
//	True when the trustee matches, false otherwise.
func (resolver *Resolver) Matches(securityIdentifier string, needle string) bool {
	if needle == "" {
		return true
	}
	needle = strings.ToLower(needle)

	if strings.Contains(strings.ToLower(securityIdentifier), needle) {
		return true
	}
	return strings.Contains(strings.ToLower(resolver.Name(securityIdentifier)), needle)
}

// qualify puts the domain in front of a name that came out of the directory.
//
// Parameters:
//
//	accountName (string): The sAMAccountName of the identity.
//
// Returns:
//
//	The qualified name, or the name as-is when no domain is known.
func (resolver *Resolver) qualify(accountName string) string {
	if resolver.domain == "" {
		return accountName
	}
	return fmt.Sprintf("%s\\%s", resolver.domain, accountName)
}

// lookup asks the directory for the sAMAccountName behind a SID.
//
// Parameters:
//
//	securityIdentifier (string): The string form of the SID.
//
// Returns:
//
//	The sAMAccountName, or an empty string when the SID could not be resolved.
func (resolver *Resolver) lookup(securityIdentifier string) string {
	if resolver.session == nil {
		return ""
	}

	filter, err := objectSIDFilter(securityIdentifier)
	if err != nil {
		logger.Debug(fmt.Sprintf("Not looking up '%s': %s", securityIdentifier, err))
		return ""
	}

	for _, searchBase := range resolver.searchBases {
		entries, err := resolver.session.QueryWholeSubtree(searchBase, filter, []string{attributeSAMAccountName})
		if err != nil {
			logger.Debug(fmt.Sprintf("Error looking up '%s' under '%s': %s", securityIdentifier, searchBase, err))
			continue
		}
		for _, entry := range entries {
			if accountName := entry.GetEqualFoldAttributeValue(attributeSAMAccountName); accountName != "" {
				return accountName
			}
		}
	}

	return ""
}

// objectSIDFilter builds the LDAP filter matching one SID.
//
// A SID is a binary attribute, so it goes into a filter as the \XX escape of each of
// its bytes rather than as its string form.
//
// Parameters:
//
//	securityIdentifier (string): The string form of the SID.
//
// Returns:
//
//	The filter, or an error if the SID could not be parsed or serialized.
func objectSIDFilter(securityIdentifier string) (string, error) {
	parsed := sid.SID{}
	if err := parsed.FromString(securityIdentifier); err != nil {
		return "", fmt.Errorf("unparseable SID '%s': %w", securityIdentifier, err)
	}

	rawSID, err := parsed.Marshal()
	if err != nil {
		return "", fmt.Errorf("could not serialize SID '%s': %w", securityIdentifier, err)
	}

	escaped := strings.Builder{}
	escaped.Grow(len(rawSID) * 3)
	for _, raw := range rawSID {
		escaped.WriteString(fmt.Sprintf("\\%02x", raw))
	}

	return fmt.Sprintf("(%s=%s)", attributeObjectSID, escaped.String()), nil
}

// UseIndex points the resolver at a newer identity index, keeping everything it has
// already looked up.
//
// A monitoring run reads the directory again on every cycle, and objects are created
// while it runs. Answering forever from the index of the first reading would leave
// every principal created since then unnamed.
//
// Parameters:
//
//	index (map[string]string): The identity index of the latest reading.
func (resolver *Resolver) UseIndex(index map[string]string) {
	if index != nil {
		resolver.index = index
	}
}
