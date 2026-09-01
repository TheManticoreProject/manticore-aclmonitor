package acls

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/winacl/ace"
)

// RenderOptions says how much of a change to print.
type RenderOptions struct {
	// ShowSDDL adds the SDDL of the descriptor before and after the change, for
	// pasting into another tool.
	ShowSDDL bool
}

// Detail is one item under the line naming the object: a headline, and the lines
// nested under it. Both are already coloured; the tree branches are added when the
// detail is printed.
type Detail struct {
	Summary string
	Bullets []string
}

// Render prints one change.
//
// The line naming the object carries the timestamp of the reading that saw it, and
// everything below it is printed without one, so the object reads as a single event.
//
// Parameters:
//
//	change (Change): The change to print.
//	resolver (*Resolver): The resolver naming the trustees.
//	options (RenderOptions): How much of the change to print.
func Render(change Change, resolver *Resolver, options RenderOptions) {
	// A distinguished name is as attacker-controlled as an attribute value is:
	// whoever can create an object picks its relative distinguished name. It goes
	// through the same sanitizing as everything else, so that a crafted name cannot
	// repaint the operator's terminal.
	distinguishedName := FormatText(change.DistinguishedName)

	switch change.Kind {
	case DescriptorAppeared:
		logger.Print(fmt.Sprintf("[\x1b[1;92m+\x1b[0m] \x1b[1;92mSecurity descriptor appeared: %s\x1b[0m", distinguishedName))
		return
	case DescriptorDisappeared:
		logger.Print(fmt.Sprintf("[\x1b[1;91m-\x1b[0m] \x1b[1;91mSecurity descriptor disappeared: %s\x1b[0m", distinguishedName))
		return
	}

	logger.Print(fmt.Sprintf("[\x1b[1;94m~\x1b[0m] \x1b[1;94mSecurity descriptor changed: %s\x1b[0m", distinguishedName))
	printDetails(Details(change, resolver, options))
}

// printDetails writes the items under the object line as a tree.
//
// Parameters:
//
//	details ([]Detail): The items to print.
func printDetails(details []Detail) {
	for index, detail := range details {
		branch, continuation := "  ├── ", "  │   "
		if index == len(details)-1 {
			branch, continuation = "  └── ", "      "
		}
		logger.Plain.Print(branch + detail.Summary)

		for bulletIndex, bullet := range detail.Bullets {
			bulletBranch := "├── "
			if bulletIndex == len(detail.Bullets)-1 {
				bulletBranch = "└── "
			}
			logger.Plain.Print(continuation + bulletBranch + bullet)
		}
	}
}

// Details renders everything found inside a changed descriptor, in a fixed order:
// what the descriptor is as a whole first (owner, group, inheritance), then what
// moved inside each of its access control lists.
//
// Parameters:
//
//	change (Change): The change to render.
//	resolver (*Resolver): The resolver naming the trustees.
//	options (RenderOptions): How much of the change to render.
//
// Returns:
//
//	The items to print under the object line.
func Details(change Change, resolver *Resolver, options RenderOptions) []Detail {
	details := []Detail{}

	if change.ParseError != nil {
		return append(details, Detail{
			Summary: fmt.Sprintf("\x1b[91mThe descriptor changed but could not be parsed: %s\x1b[0m", FormatText(change.ParseError.Error())),
		})
	}

	if change.Owner != nil {
		details = append(details, Detail{Summary: describeIdentityChange("Owner", change.Owner, resolver)})
	}
	if change.Group != nil {
		details = append(details, Detail{Summary: describeIdentityChange("Group", change.Group, resolver)})
	}
	if change.ControlFlags != nil {
		details = append(details, describeFlagsChange(change.ControlFlags)...)
	}

	details = append(details, describeACLChanges(DACL, change.DACL, resolver)...)
	details = append(details, describeACLChanges(SACL, change.SACL, resolver)...)

	if options.ShowSDDL {
		details = append(details, describeSDDL(change)...)
	}

	if formatted := FormatDirectoryTime(change.WhenChanged); formatted != "" {
		details = append(details, Detail{Summary: fmt.Sprintf("The directory recorded the write at \x1b[93m%s\x1b[0m", formatted)})
	}

	return details
}

// describeIdentityChange renders an owner or a group moving.
//
// Parameters:
//
//	label (string): "Owner" or "Group".
//	change (*IdentityChange): The change to render.
//	resolver (*Resolver): The resolver naming the identities.
//
// Returns:
//
//	The line to print.
func describeIdentityChange(label string, change *IdentityChange, resolver *Resolver) string {
	switch {
	case change.Before == "":
		return fmt.Sprintf("%s was set to \x1b[94m%s\x1b[0m", label, resolver.Display(change.After))
	case change.After == "":
		return fmt.Sprintf("\x1b[91m%s was removed\x1b[0m (was \x1b[94m%s\x1b[0m)", label, resolver.Display(change.Before))
	default:
		return fmt.Sprintf("%s changed from \x1b[94m%s\x1b[0m to \x1b[94m%s\x1b[0m", label, resolver.Display(change.Before), resolver.Display(change.After))
	}
}

// describeFlagsChange renders the control field of a descriptor moving.
//
// The two protected flags get a sentence of their own rather than being listed as
// flag names: turning SE_DACL_PROTECTED on is breaking inheritance, which is the
// thing an operator is looking for, and it does not read as such from its name.
//
// Parameters:
//
//	change (*FlagsChange): The change to render.
//
// Returns:
//
//	The items to print.
func describeFlagsChange(change *FlagsChange) []Detail {
	details := []Detail{}

	for _, flag := range change.Set {
		switch flag {
		case "DACL Protected":
			details = append(details, Detail{Summary: "\x1b[91mInheritance was broken: the object no longer receives the ACEs of its parent (SE_DACL_PROTECTED set)\x1b[0m"})
		case "SACL Protected":
			details = append(details, Detail{Summary: "\x1b[91mAudit inheritance was broken: the object no longer receives the audit ACEs of its parent (SE_SACL_PROTECTED set)\x1b[0m"})
		default:
			details = append(details, Detail{Summary: fmt.Sprintf("Control flag \x1b[93m%s\x1b[0m was set", flag)})
		}
	}

	for _, flag := range change.Cleared {
		switch flag {
		case "DACL Protected":
			details = append(details, Detail{Summary: "Inheritance was restored: the object receives the ACEs of its parent again (SE_DACL_PROTECTED cleared)"})
		case "SACL Protected":
			details = append(details, Detail{Summary: "Audit inheritance was restored: the object receives the audit ACEs of its parent again (SE_SACL_PROTECTED cleared)"})
		default:
			details = append(details, Detail{Summary: fmt.Sprintf("Control flag \x1b[93m%s\x1b[0m was cleared", flag)})
		}
	}

	return details
}

// describeACLChanges renders everything that moved inside one access control list.
//
// Parameters:
//
//	kind (ACLKind): Which list this is.
//	changes (ACLChanges): What moved in it.
//	resolver (*Resolver): The resolver naming the trustees.
//
// Returns:
//
//	The items to print.
func describeACLChanges(kind ACLKind, changes ACLChanges, resolver *Resolver) []Detail {
	details := []Detail{}

	if changes.Presence != "" {
		details = append(details, Detail{Summary: fmt.Sprintf("\x1b[91m%s\x1b[0m", changes.Presence)})
	}

	for _, entry := range changes.Added {
		details = append(details, Detail{
			Summary: fmt.Sprintf("[\x1b[1;92m+\x1b[0m] %s ACE added: %s", kind, describeAceHead(entry, resolver)),
			Bullets: describeWholeAce(entry, "+"),
		})
	}

	for _, change := range changes.Changed {
		// The scope line belongs to the entry, not to either direction, so it is
		// emitted once above both rather than by each of the two calls below.
		bullets := inheritedScopeBullets(change.After)
		bullets = append(bullets, describeRightBullets(DescribeMask(change.Granted, change.After), "+")...)
		bullets = append(bullets, describeRightBullets(DescribeMask(change.Revoked, change.Before), "-")...)
		details = append(details, Detail{
			Summary: fmt.Sprintf("[\x1b[1;94m~\x1b[0m] %s ACE changed: %s", kind, describeAceHead(change.After, resolver)),
			Bullets: bullets,
		})
	}

	for _, entry := range changes.Removed {
		details = append(details, Detail{
			Summary: fmt.Sprintf("[\x1b[1;91m-\x1b[0m] %s ACE removed: %s", kind, describeAceHead(entry, resolver)),
			Bullets: describeWholeAce(entry, "-"),
		})
	}

	return details
}

// describeAceHead renders the headline of an ACE: what it does, to whom, and under
// which inheritance flags.
//
// Parameters:
//
//	entry (*ace.AccessControlEntry): The entry to render.
//	resolver (*Resolver): The resolver naming the trustee.
//
// Returns:
//
//	The headline.
func describeAceHead(entry *ace.AccessControlEntry, resolver *Resolver) string {
	head := fmt.Sprintf("%s \x1b[94m%s\x1b[0m", AceVerb(entry), resolver.Display(entry.Identity.SID.ToString()))

	// An ACE with no flag set is described by winacl as carrying the flag "NONE",
	// which is true and says nothing. Only real flags are worth the space.
	if entry.Header.Flags.RawValue != 0 && len(entry.Header.Flags.Flags) > 0 {
		head += fmt.Sprintf(" [\x1b[93m%s\x1b[0m]", FormatText(strings.Join(entry.Header.Flags.Flags, ", ")))
	}

	return head
}

// describeWholeAce renders every right an ACE carries, which is what an entry that
// was added or removed in one piece needs.
//
// Parameters:
//
//	entry (*ace.AccessControlEntry): The entry to render.
//	marker (string): "+" when the entry was added, "-" when it was removed.
//
// Returns:
//
//	The bullets to print.
func describeWholeAce(entry *ace.AccessControlEntry, marker string) []string {
	descriptions := DescribeAce(entry)

	bullets := inheritedScopeBullets(entry)
	bullets = append(bullets, describeRightBullets(descriptions, marker)...)

	// An ACE granting nothing is a real thing to find in a directory, and it is worth
	// saying so rather than printing an entry with nothing under it. This is only
	// said for a whole entry: a re-masked one with nothing granted has its
	// revocations to show, and would otherwise claim its mask was empty.
	if len(descriptions) == 0 {
		bullets = append(bullets, "No access rights are set in the mask")
	}

	return bullets
}

// inheritedScopeBullets renders the class an ACE is restricted to inheriting onto, if
// it names one.
//
// It changes who the ACE reaches rather than what it grants, so it is stated once for
// the entry rather than repeated against each right.
//
// Parameters:
//
//	entry (*ace.AccessControlEntry): The entry to render.
//
// Returns:
//
//	One bullet, or none when the entry names no inherited object type.
func inheritedScopeBullets(entry *ace.AccessControlEntry) []string {
	inheritedType := InheritedObjectTypeOf(entry)
	if inheritedType == "" {
		return []string{}
	}
	return []string{fmt.Sprintf("Applies only to \x1b[93m%s\x1b[0m objects below this one", FormatText(inheritedType))}
}

// describeRightBullets renders a set of rights as one bullet each, marked with the
// direction they moved in.
//
// Parameters:
//
//	descriptions ([]RightDescription): The rights to render.
//	marker (string): "+" when the rights were granted, "-" when they were revoked.
//
// Returns:
//
//	The bullets to print, one per right.
func describeRightBullets(descriptions []RightDescription, marker string) []string {
	colour := "\x1b[92m"
	if marker == "-" {
		colour = "\x1b[91m"
	}

	bullets := make([]string, 0, len(descriptions))
	for _, description := range descriptions {
		text := FormatText(description.Text)
		if description.Notable {
			text = fmt.Sprintf("\x1b[91m%s\x1b[0m", text)
		}
		bullets = append(bullets, fmt.Sprintf("%s%s\x1b[0m %s", colour, marker, text))
	}
	return bullets
}

// describeSDDL renders the descriptor before and after the change, for pasting into
// another tool.
//
// Parameters:
//
//	change (Change): The change to render.
//
// Returns:
//
//	The items to print, empty when neither side could be serialized.
func describeSDDL(change Change) []Detail {
	detail := Detail{Summary: "SDDL"}

	if change.Before != nil {
		if sddl, err := change.Before.ToSDDLString(); err == nil {
			detail.Bullets = append(detail.Bullets, fmt.Sprintf("\x1b[91mbefore\x1b[0m %s", FormatText(sddl)))
		}
	}
	if change.After != nil {
		if sddl, err := change.After.ToSDDLString(); err == nil {
			detail.Bullets = append(detail.Bullets, fmt.Sprintf("\x1b[92mafter\x1b[0m  %s", FormatText(sddl)))
		}
	}

	if len(detail.Bullets) == 0 {
		return []Detail{}
	}
	return []Detail{detail}
}

// FormatDirectoryTime renders an LDAP generalized time as a readable date.
//
// Parameters:
//
//	value (string): The attribute value, as in "20260901142203.0Z".
//
// Returns:
//
//	The formatted date, or an empty string when the value is absent or is not a
//	generalized time.
func FormatDirectoryTime(value string) string {
	if value == "" {
		return ""
	}

	parsed, err := time.Parse("20060102150405.0Z", value)
	if err != nil {
		// Some servers write the value without the fractional second.
		parsed, err = time.Parse("20060102150405Z", value)
		if err != nil {
			return FormatText(value)
		}
	}

	return parsed.UTC().Format("2006-01-02 15:04:05 UTC")
}

// FormatText renders text that came out of the directory as safe terminal text.
//
// Only the characters that are not printable are replaced, each by its \xNN escape,
// because a distinguished name, a trustee name or a right is text the operator has to
// be able to read. What it prevents is a name carrying an ANSI escape sequence, which
// would otherwise clear the screen and hide the change that had just been reported.
//
// Parameters:
//
//	text (string): The raw text.
//
// Returns:
//
//	The text with every non-printable character escaped.
func FormatText(text string) string {
	if isPrintable(text) {
		return text
	}

	var sanitized strings.Builder
	sanitized.Grow(len(text))
	for index := 0; index < len(text); index++ {
		character, size := utf8.DecodeRuneInString(text[index:])
		// RuneError with a size of 1 is a byte that is not valid UTF-8 at all, so it
		// is escaped as the raw byte it is rather than as a rune.
		if character == utf8.RuneError && size == 1 {
			sanitized.WriteString(fmt.Sprintf("\\x%02x", text[index]))
			continue
		}
		if unicode.IsPrint(character) {
			sanitized.WriteString(text[index : index+size])
		} else {
			for _, raw := range []byte(text[index : index+size]) {
				sanitized.WriteString(fmt.Sprintf("\\x%02x", raw))
			}
		}
		index += size - 1
	}
	return sanitized.String()
}

// isPrintable reports whether text can be written to a terminal as-is.
//
// Parameters:
//
//	text (string): The text to check.
//
// Returns:
//
//	True when the text is valid UTF-8 holding no control character, false otherwise.
func isPrintable(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	for _, character := range text {
		if !unicode.IsPrint(character) && character != '\t' {
			return false
		}
	}
	return true
}
