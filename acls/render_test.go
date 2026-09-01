package acls

import (
	"strings"
	"testing"
)

// renderedLines returns every line the details of a change would print, with the ANSI
// escapes stripped, which is what a test asserts on.
//
// Parameters:
//
//	t (*testing.T): The test.
//	change (Change): The change to render.
//	resolver (*Resolver): The resolver naming the trustees.
//	options (RenderOptions): How much of the change to render.
//
// Returns:
//
//	The lines, summaries and bullets together.
func renderedLines(t *testing.T, change Change, resolver *Resolver, options RenderOptions) []string {
	t.Helper()

	lines := []string{}
	for _, detail := range Details(change, resolver, options) {
		lines = append(lines, stripANSI(detail.Summary))
		for _, bullet := range detail.Bullets {
			lines = append(lines, stripANSI(bullet))
		}
	}
	return lines
}

// stripANSI removes the colour escapes from a rendered line.
//
// Parameters:
//
//	line (string): The line to strip.
//
// Returns:
//
//	The line without any escape sequence.
func stripANSI(line string) string {
	stripped := strings.Builder{}
	for index := 0; index < len(line); index++ {
		if line[index] == 0x1b {
			for index < len(line) && line[index] != 'm' {
				index++
			}
			continue
		}
		stripped.WriteByte(line[index])
	}
	return stripped.String()
}

// containsLine reports whether any line holds a substring.
//
// Parameters:
//
//	lines ([]string): The lines to search.
//	needle (string): What to look for.
//
// Returns:
//
//	True when at least one line holds it.
func containsLine(lines []string, needle string) bool {
	for _, line := range lines {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

// TestRenderNamesTheTrusteeAndTheAttack checks the shape of the output that is the
// point of the tool: who got what, in words.
func TestRenderNamesTheTrusteeAndTheAttack(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")(OA;;CR;" + guidReplicationGetChangesAll + ";;" + sidBob + ")"})

	resolver := testResolver(map[string]string{sidBob: "svc_backup"})
	lines := renderedLines(t, onlyChange(t, Diff(before, after, DiffOptions{})), resolver, RenderOptions{})

	if !containsLine(lines, "DACL ACE added: Allow MANTICORE.local\\svc_backup ("+sidBob+")") {
		t.Errorf("expected the added ACE to name its trustee, got %q", lines)
	}
	if !containsLine(lines, "DCSync") {
		t.Errorf("expected the right to be rendered as the attack it enables, got %q", lines)
	}
}

// TestRenderMarksGrantedAndRevokedRights checks that a re-masked ACE shows which way
// each right moved.
func TestRenderMarksGrantedAndRevokedRights(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidBob + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;WDWO;;;" + sidBob + ")"})

	lines := renderedLines(t, onlyChange(t, Diff(before, after, DiffOptions{})), testResolver(nil), RenderOptions{})

	if !containsLine(lines, "+ Can rewrite the ACL of the object (WriteDacl)") {
		t.Errorf("expected the granted right to be marked with +, got %q", lines)
	}
	if !containsLine(lines, "- Can read every attribute of the object") {
		t.Errorf("expected the revoked right to be marked with -, got %q", lines)
	}
}

// TestRenderSpellsOutBrokenInheritance checks that the control flag is rendered as
// what it means, not as its name.
func TestRenderSpellsOutBrokenInheritance(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:AI(A;;RP;;;" + sidAlice + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:PAI(A;;RP;;;" + sidAlice + ")"})

	lines := renderedLines(t, onlyChange(t, Diff(before, after, DiffOptions{})), testResolver(nil), RenderOptions{})
	if !containsLine(lines, "Inheritance was broken") {
		t.Errorf("expected the broken inheritance to be spelled out, got %q", lines)
	}
}

// TestRenderShowsTheSidWhenTheNameIsUnknown checks that an unresolvable trustee still
// renders, as the SID it is.
func TestRenderShowsTheSidWhenTheNameIsUnknown(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")(A;;WP;;;" + sidBob + ")"})

	lines := renderedLines(t, onlyChange(t, Diff(before, after, DiffOptions{})), testResolver(nil), RenderOptions{})
	if !containsLine(lines, "Allow "+sidBob) {
		t.Errorf("expected the bare SID to be shown, got %q", lines)
	}
}

// TestRenderNeutralizesEscapeSequences is the terminal-safety guard. A name is
// attacker-controlled: whoever can create an object picks its relative distinguished
// name, and a sAMAccountName carrying an ANSI escape would otherwise clear the screen
// and hide the change that had just been reported.
func TestRenderNeutralizesEscapeSequences(t *testing.T) {
	hostile := "canary\x1b[2Jwiped"

	if got := FormatText(hostile); strings.ContainsRune(got, 0x1b) {
		t.Errorf("FormatText left an escape byte in the output: %q", got)
	}
	if got := FormatText(hostile); !strings.Contains(got, "\\x1b") {
		t.Errorf("FormatText should escape the byte rather than drop it, got %q", got)
	}

	// And through the resolver, which is how a hostile sAMAccountName reaches a line.
	resolver := testResolver(map[string]string{sidBob: hostile})
	if got := resolver.Display(sidBob); strings.ContainsRune(got, 0x1b) {
		t.Errorf("Display left an escape byte in the output: %q", got)
	}
}

// TestFormatTextLeavesOrdinaryTextAlone checks the common path is not mangled.
func TestFormatTextLeavesOrdinaryTextAlone(t *testing.T) {
	for _, text := range []string{targetDN, "MANTICORE.local\\jdoe", "Domain Admins", ""} {
		if got := FormatText(text); got != text {
			t.Errorf("FormatText(%q) = %q, want it unchanged", text, got)
		}
	}
}

// TestFormatDirectoryTime checks the whenChanged rendering, in both the forms a
// domain controller writes it, and the fallback for anything else.
func TestFormatDirectoryTime(t *testing.T) {
	testCases := []struct {
		value string
		want  string
	}{
		{"20260901142203.0Z", "2026-09-01 14:22:03 UTC"},
		{"20260901142203Z", "2026-09-01 14:22:03 UTC"},
		{"", ""},
		{"not a timestamp", "not a timestamp"},
	}

	for _, testCase := range testCases {
		if got := FormatDirectoryTime(testCase.value); got != testCase.want {
			t.Errorf("FormatDirectoryTime(%q) = %q, want %q", testCase.value, got, testCase.want)
		}
	}
}

// TestRenderShowsSDDLOnlyWhenAsked checks the option.
func TestRenderShowsSDDLOnlyWhenAsked(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;WP;;;" + sidAlice + ")"})
	change := onlyChange(t, Diff(before, after, DiffOptions{}))

	if lines := renderedLines(t, change, testResolver(nil), RenderOptions{}); containsLine(lines, "SDDL") {
		t.Errorf("the SDDL must not be printed unless asked for, got %q", lines)
	}

	lines := renderedLines(t, change, testResolver(nil), RenderOptions{ShowSDDL: true})
	if !containsLine(lines, "SDDL") || !containsLine(lines, "before O:BAG:BAD:") {
		t.Errorf("expected the SDDL of both sides, got %q", lines)
	}
}

// TestRenderReportsAParseFailureAndNothingElse checks that a descriptor the library
// cannot read says so, rather than printing an empty change.
func TestRenderReportsAParseFailureAndNothingElse(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidAlice + ")"})
	after := NewSnapshot()
	after.Objects[targetDN] = &ObjectSecurity{RawDescriptor: []byte{0x01, 0x00, 0x04, 0x80}}

	lines := renderedLines(t, onlyChange(t, Diff(before, after, DiffOptions{})), testResolver(nil), RenderOptions{})
	if len(lines) != 1 || !strings.Contains(lines[0], "could not be parsed") {
		t.Errorf("expected exactly one line saying the descriptor could not be parsed, got %q", lines)
	}
}

// TestRenderOmitsTheEmptyAceFlagList checks that an ACE with no flag set does not
// carry a "[NONE]" that says nothing, while one with real flags still shows them.
func TestRenderOmitsTheEmptyAceFlagList(t *testing.T) {
	resolver := testResolver(nil)

	// Stripped first: the colour escapes themselves contain a bracket.
	plain := stripANSI(describeAceHead(firstAce(t, "O:BAG:BAD:(A;;RP;;;"+sidBob+")"), resolver))
	if strings.Contains(plain, "[") {
		t.Errorf("an ACE with no flags must carry no flag list, got %q", plain)
	}

	inherited := describeAceHead(firstAce(t, "O:BAG:BAD:(A;CIID;RP;;;"+sidBob+")"), resolver)
	if !strings.Contains(stripANSI(inherited), "INHERITED") {
		t.Errorf("an ACE with real flags must show them, got %q", stripANSI(inherited))
	}
}

// TestRenderStatesTheInheritedScopeOnce checks that the line saying which class an ACE
// reaches belongs to the entry, not to a direction: a re-masked ACE has both a granted
// and a revoked side, and the scope must not be printed once for each.
func TestRenderStatesTheInheritedScopeOnce(t *testing.T) {
	const userClass = "bf967aba-0de6-11d0-a285-00aa003049e2"
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(OA;CI;WPRP;" + guidMember + ";" + userClass + ";" + sidBob + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(OA;CI;WP;" + guidMember + ";" + userClass + ";" + sidBob + ")"})

	lines := renderedLines(t, onlyChange(t, Diff(before, after, DiffOptions{})), testResolver(nil), RenderOptions{})

	occurrences := 0
	for _, line := range lines {
		if strings.Contains(line, "Applies only to") {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Errorf("the inherited scope must be stated exactly once, got %d times in %q", occurrences, lines)
	}
	// It is a class, not an attribute, whatever table winacl resolved the GUID from.
	if !containsLine(lines, "Applies only to user objects below this one") {
		t.Errorf("expected the class to be named plainly, got %q", lines)
	}
}

// TestRenderDoesNotClaimAnEmptyMaskOnARevokeOnlyChange checks the other half of that
// split: an ACE that only lost rights has its revocations to show, and must not also
// claim that no rights are set in its mask.
func TestRenderDoesNotClaimAnEmptyMaskOnARevokeOnlyChange(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RPWP;;;" + sidBob + ")"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;RP;;;" + sidBob + ")"})

	lines := renderedLines(t, onlyChange(t, Diff(before, after, DiffOptions{})), testResolver(nil), RenderOptions{})
	if containsLine(lines, "No access rights are set") {
		t.Errorf("a revoke-only change must not claim an empty mask, got %q", lines)
	}
	if !containsLine(lines, "- Can write every attribute of the object") {
		t.Errorf("expected the revoked right to be shown, got %q", lines)
	}
}

// TestRenderReportsAnAceThatGrantsNothing checks that the fallback still fires where
// it belongs: a whole ACE carrying no right at all.
func TestRenderReportsAnAceThatGrantsNothing(t *testing.T) {
	before := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:"})
	after := snapshotOf(t, map[string]string{targetDN: "O:BAG:BAD:(A;;;;;" + sidBob + ")"})

	change := onlyChange(t, Diff(before, after, DiffOptions{}))
	if len(change.DACL.Added) != 1 {
		t.Skipf("the SDDL parser did not produce an empty-mask ACE: %+v", change.DACL)
	}

	lines := renderedLines(t, change, testResolver(nil), RenderOptions{})
	if !containsLine(lines, "No access rights are set in the mask") {
		t.Errorf("an ACE granting nothing should say so, got %q", lines)
	}
}
