// Package cli holds the command line helpers of the tool: the argument groups shared
// between modes, and the interactive prompts.
//
// goopts does not inherit flags from a parent parser, so every flag has to be
// registered on each sub-parser that uses it. These helpers register a whole group at
// once, so the three modes do not each carry their own copy of the same declarations.
//
// The helpers take POINTERS to the package-level variables declared in main.go. That
// is the goopts contract: the parser writes into those variables during ap.Parse().
// Keep all flag storage in main.go and pass it down here.
package cli

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
)

// RegisterConfigurationGroup registers the "Configuration" argument group, which
// every mode carries, diff included.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	debug (*bool): Whether to print debug information.
//	noColors (*bool): Whether to print the output without colors.
//	logFile (*string): The file to append the output to.
func RegisterConfigurationGroup(subparser *parser.ArgumentsParser, debug *bool, noColors *bool, logFile *string) {
	group, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
	group.NewBoolArgument(noColors, "", "--no-colors", false, "Print the output without colors.")
	group.NewStringArgument(logFile, "-l", "--logfile", "", false, "Log file to append the output to.")
}

// RegisterLDAPConnectionSettingsGroup registers the "LDAP Connection Settings"
// argument group.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	domainController (*string): The hostname or IP address of the domain controller.
//	dcHost (*string): The FQDN of the domain controller, for the Kerberos SPN.
//	ldapPort (*int): The port to connect to on the LDAP server.
//	useLdaps (*bool): Whether to use LDAPS instead of LDAP.
//	useKerberos (*bool): Whether to use Kerberos instead of NTLM.
//	useSealing (*bool): Whether to encrypt a Kerberos session rather than only sign it.
func RegisterLDAPConnectionSettingsGroup(subparser *parser.ArgumentsParser, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, useSealing *bool) {
	group, err := subparser.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(domainController, "-dc", "--dc-ip", "", true, "IP address or hostname of the domain controller to read, which is also the KDC (Key Distribution Center) used for Kerberos.")
	group.NewStringArgument(dcHost, "", "--dc-host", "", false, "FQDN of the domain controller, used to build the Kerberos SPN when connecting by IP with -k.")
	group.NewTcpPortArgument(ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
	group.NewBoolArgument(useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
	group.NewBoolArgument(useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	group.NewBoolArgument(useSealing, "", "--use-sealing", false, "Encrypt the LDAP traffic of a Kerberos session (GSSAPI confidentiality) instead of only signing it. Ignored with -L.")
}

// RegisterAuthenticationGroup registers the "Authentication" and "Secret" argument
// groups.
//
// Every secret is registered as optional, and --no-pass sits beside them: a tool that
// makes -p required forces the password into argv, where the process list exposes it.
// main() calls cli.ResolvePassword instead and asks for it on the terminal.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the groups on.
//	authDomain (*string): The domain to authenticate to.
//	authUsername (*string): The user to authenticate as.
//	authNoPass (*bool): Whether to skip the password prompt.
//	authPassword (*string): The password to authenticate with.
//	authHashes (*string): The LM:NT hashes to authenticate with.
//	authAesKey (*string): The AES key to authenticate with.
//	ticketCCache (*string): The path to a ccache holding a TGT.
//	ticketKirbi (*string): The path to a .kirbi file holding a TGT.
func RegisterAuthenticationGroup(subparser *parser.ArgumentsParser, authDomain *string, authUsername *string, authNoPass *bool, authPassword *string, authHashes *string, authAesKey *string, ticketCCache *string, ticketKirbi *string) {
	if group, err := subparser.NewArgumentGroup("Authentication"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group.NewStringArgument(authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		group.NewStringArgument(authUsername, "-u", "--username", "", true, "User to authenticate as.")
		// --no-pass selects "no password", it does not supply a secret, so it does
		// not belong in the mutually exclusive Secret group: its job is to suppress
		// the prompt for a run that is meant to bind without one.
		group.NewBoolArgument(authNoPass, "", "--no-pass", false, "Do not ask for a password, bind without one.")
	}

	// At most one secret, and none is allowed: a run without one is asked for the
	// password on the terminal rather than being refused, so that the secret does not
	// have to be written into argv.
	if group, err := subparser.NewNotRequiredMutuallyExclusiveArgumentGroup("Secret"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		group.NewStringArgument(authAesKey, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
		group.NewStringArgument(ticketCCache, "", "--ticket-ccache", "", false, "Path to a Kerberos credential cache (ccache) holding a TGT for pass-the-ticket (implies -k).")
		group.NewStringArgument(ticketKirbi, "", "--ticket-kirbi", "", false, "Path to a .kirbi file holding a TGT for pass-the-ticket (implies -k).")
	}
}

// RegisterScopeGroup registers the "Scope" argument group: what to read from the
// directory. It is carried by the two modes that connect.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	searchBase (*string): The distinguished name to read.
//	ldapFilter (*string): The filter restricting which objects are read.
//	includeSacl (*bool): Whether to also read the system access control list.
func RegisterScopeGroup(subparser *parser.ArgumentsParser, searchBase *string, ldapFilter *string, includeSacl *bool) {
	group, err := subparser.NewArgumentGroup("Scope")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(searchBase, "-S", "--search-base", "", false, "Distinguished name to read. If omitted, every naming context of the domain controller is read.")
	group.NewStringArgument(ldapFilter, "-f", "--ldap-filter", "(objectClass=*)", false, "LDAP filter restricting which objects are read.")
	group.NewBoolArgument(includeSacl, "", "--include-sacl", false, "Also read and compare the SACL. Requires SeSecurityPrivilege: without it the domain controller returns no security descriptor at all.")
}

// RegisterReportingGroup registers the "Reporting" argument group: what to show out
// of everything that changed. It is carried by the two modes that report changes.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	ignoreInherited (*bool): Whether to drop the changes to inherited ACEs.
//	onlyNotable (*bool): Whether to keep only the notable changes.
//	trustee (*string): The trustee to restrict the reported ACEs to.
//	showSddl (*bool): Whether to also print the SDDL of a changed descriptor.
func RegisterReportingGroup(subparser *parser.ArgumentsParser, ignoreInherited *bool, onlyNotable *bool, trustee *string, showSddl *bool) {
	group, err := subparser.NewArgumentGroup("Reporting")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewBoolArgument(ignoreInherited, "", "--ignore-inherited", false, "Do not report changes to inherited ACEs. One write to a container lands on every object below it; this shows the write instead of the storm.")
	group.NewBoolArgument(onlyNotable, "", "--only-notable", false, "Report only the changes that move a right which hands somebody control of the object or of the identity behind it.")
	group.NewStringArgument(trustee, "", "--trustee", "", false, "Report only the ACEs whose trustee matches this SID, name or substring.")
	group.NewBoolArgument(showSddl, "", "--sddl", false, "Also print the SDDL of the descriptor before and after the change.")
}

// Flags bundles the pointers to the flag variables declared in main.go.
//
// The goopts contract is that the parser writes into the caller's variables, and the
// convention is that those variables live in main.go. With three modes drawing on
// twenty-six flags between them, threading them as individual parameters through each
// mode's SetupSubParser produces signatures nobody can read or call correctly, so they
// travel as one struct of pointers instead. The storage is still main.go's, and the
// parser still writes straight into it.
type Flags struct {
	// Configuration
	Debug    *bool
	NoColors *bool
	LogFile  *string

	// LDAP Connection Settings
	DomainController *string
	DCHost           *string
	LDAPPort         *int
	UseLdaps         *bool
	UseKerberos      *bool
	UseSealing       *bool

	// Authentication
	AuthDomain   *string
	AuthUsername *string
	AuthNoPass   *bool
	AuthPassword *string
	AuthHashes   *string
	AuthAesKey   *string
	TicketCCache *string
	TicketKirbi  *string

	// Scope
	SearchBase  *string
	LDAPFilter  *string
	IncludeSacl *bool

	// Query delay
	TimeDelay      *int
	RandomizeDelay *bool

	// Reporting
	IgnoreInherited *bool
	OnlyNotable     *bool
	Trustee         *string
	ShowSddl        *bool

	// Files
	OutputFile *string
	BeforeFile *string
	AfterFile  *string
}

// RegisterConnectionGroups attaches the groups every mode that talks to a domain
// controller carries: the configuration, the LDAP connection settings, the
// authentication and the secret.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the groups on.
//	flags (*Flags): The flag storage to bind to.
func RegisterConnectionGroups(subparser *parser.ArgumentsParser, flags *Flags) {
	RegisterConfigurationGroup(subparser, flags.Debug, flags.NoColors, flags.LogFile)
	RegisterLDAPConnectionSettingsGroup(subparser, flags.DomainController, flags.DCHost, flags.LDAPPort, flags.UseLdaps, flags.UseKerberos, flags.UseSealing)
	RegisterAuthenticationGroup(subparser, flags.AuthDomain, flags.AuthUsername, flags.AuthNoPass, flags.AuthPassword, flags.AuthHashes, flags.AuthAesKey, flags.TicketCCache, flags.TicketKirbi)
}
