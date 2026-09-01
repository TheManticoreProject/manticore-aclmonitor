package main

import (
	"fmt"
	"net"
	"os"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-aclmonitor/acls"
	"github.com/TheManticoreProject/manticore-aclmonitor/cli"
	"github.com/TheManticoreProject/manticore-aclmonitor/config"
	"github.com/TheManticoreProject/manticore-aclmonitor/modes/mode_diff"
	"github.com/TheManticoreProject/manticore-aclmonitor/modes/mode_monitor"
	"github.com/TheManticoreProject/manticore-aclmonitor/modes/mode_snapshot"
)

// VERSION is the version of the tool, shown in the banner and recorded in every
// snapshot file it writes.
const VERSION = "1.0.0"

var (
	// mode is the first positional argument: monitor, snapshot or diff.
	mode string

	// Configuration
	debug    bool
	noColors bool
	logFile  string

	// LDAP Connection Settings
	domainController string
	dcHost           string
	ldapPort         int
	useLdaps         bool
	useKerberos      bool
	useSealing       bool

	// Authentication
	authDomain   string
	authUsername string
	authNoPass   bool
	authPassword string
	authHashes   string
	authAesKey   string
	ticketCCache string
	ticketKirbi  string

	// Scope
	searchBase  string
	ldapFilter  string
	includeSacl bool

	// Query delay
	timeDelay      int
	randomizeDelay bool

	// Reporting
	ignoreInherited bool
	onlyNotable     bool
	trustee         string
	showSddl        bool

	// Files
	outputFile string
	beforeFile string
	afterFile  string
)

// flags bundles the pointers goopts writes into. The storage above is main's; this is
// only the handle the mode parsers are given.
var flags = cli.Flags{
	Debug:    &debug,
	NoColors: &noColors,
	LogFile:  &logFile,

	DomainController: &domainController,
	DCHost:           &dcHost,
	LDAPPort:         &ldapPort,
	UseLdaps:         &useLdaps,
	UseKerberos:      &useKerberos,
	UseSealing:       &useSealing,

	AuthDomain:   &authDomain,
	AuthUsername: &authUsername,
	AuthNoPass:   &authNoPass,
	AuthPassword: &authPassword,
	AuthHashes:   &authHashes,
	AuthAesKey:   &authAesKey,
	TicketCCache: &ticketCCache,
	TicketKirbi:  &ticketKirbi,

	SearchBase:  &searchBase,
	LDAPFilter:  &ldapFilter,
	IncludeSacl: &includeSacl,

	TimeDelay:      &timeDelay,
	RandomizeDelay: &randomizeDelay,

	IgnoreInherited: &ignoreInherited,
	OnlyNotable:     &onlyNotable,
	Trustee:         &trustee,
	ShowSddl:        &showSddl,

	OutputFile: &outputFile,
	BeforeFile: &beforeFile,
	AfterFile:  &afterFile,
}

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: fmt.Sprintf("manticore-aclmonitor - by Remi GASCOU (Podalirius) @ TheManticoreProject - v%s", VERSION),
	}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)

	ap.SetupSubParsing("mode", &mode, true)

	mode_monitor.SetupSubParser(&ap, &flags)
	mode_snapshot.SetupSubParser(&ap, &flags)
	mode_diff.SetupSubParser(&ap, &flags)

	ap.Parse()

	// LDAPS listens on 636, so selecting it moves the port unless the caller named
	// one explicitly.
	if !ap.ArgumentIsPresent("--ldap-port") {
		if useLdaps {
			ldapPort = 636
		} else {
			ldapPort = 389
		}
	}
}

func main() {
	parseArgs()

	// The logger emits every level by default, so --debug has to raise the floor
	// itself: without this, logger.Debug output appears in runs that did not ask for
	// it. LevelPrint sits above all others, so results are never filtered either way.
	if debug {
		logger.SetLevel(logger.LevelDebug)
	} else {
		logger.SetLevel(logger.LevelInfo)
	}

	// A change is timestamped to the second: the tool cannot resolve when a change
	// landed any finer than the delay between two readings.
	logger.SetTimePrecision(logger.Seconds)

	if noColors {
		logger.SetNoColors(true)
	}

	if logFile != "" {
		if err := logger.LogToFile(logFile); err != nil {
			logger.Warn(fmt.Sprintf("Error opening log file: %s", err))
			os.Exit(1)
		}
		defer logger.CloseLogFile()
	}

	cfg := config.Config{
		Debug:   debug,
		Version: VERSION,
		Network: config.Network{
			LDAP: config.LDAP{
				UseLdaps:    useLdaps,
				UseKerberos: useKerberos,
				UseSealing:  useSealing,
				LDAPPort:    ldapPort,
				SPNHostname: dcHost,
			},
			DomainController: domainController,
			Domain:           authDomain,
		},
		SearchBase: searchBase,
		Scope: acls.Scope{
			LDAPFilter:  ldapFilter,
			IncludeSACL: includeSacl,
		},
		IgnoreInherited: ignoreInherited,
		Monitoring: config.Monitoring{
			TimeDelay:      timeDelay,
			RandomizeDelay: randomizeDelay,
		},
		Reporting: acls.Reporting{
			OnlyNotable: onlyNotable,
			Trustee:     trustee,
		},
		ShowSDDL:   showSddl,
		OutputFile: outputFile,
		BeforeFile: beforeFile,
		AfterFile:  afterFile,
	}

	// diff mode reads two files and talks to nothing, so it neither asks for a
	// password nor builds credentials. Everything below this point is about
	// connecting to a domain controller.
	if mode == "diff" {
		if err := mode_diff.Run(cfg); err != nil {
			logger.Warn(fmt.Sprintf("Error in diff mode: %s", err))
			os.Exit(1)
		}
		logger.Print("Done.")
		return
	}

	// No secret on the command line means asking for one, unless the caller said not
	// to. A ticket or an AES key is itself the secret, so no prompt happens then.
	if err := cli.ResolvePassword(authDomain, authUsername, &authPassword, authNoPass, authHashes, authAesKey, ticketCCache, ticketKirbi); err != nil {
		logger.Warn(err.Error())
		os.Exit(1)
	}
	if authNoPass && authPassword == "" && authHashes == "" && authAesKey == "" && ticketCCache == "" && ticketKirbi == "" {
		logger.Warn("No secret was provided and --no-pass is set: the bind will be unauthenticated, which a domain controller will not let read a security descriptor.")
	}

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating credentials struct: %s", err))
		os.Exit(1)
	}

	// An AES key is only usable over Kerberos, so requesting one implies -k rather
	// than being a separate choice the caller has to remember to make.
	if len(authAesKey) > 0 {
		if err := creds.SetAESKey(authAesKey); err != nil {
			logger.Warn(fmt.Sprintf("Error setting AES key: %s", err))
			os.Exit(1)
		}
		if !useKerberos {
			logger.Debug("An AES key was supplied, enabling Kerberos authentication")
			useKerberos = true
		}
	}

	// A Kerberos ticket (ccache or .kirbi) is itself the credential for
	// pass-the-ticket and only works over Kerberos, so supplying one implies -k, just
	// like an AES key.
	if len(ticketCCache) > 0 {
		if err := creds.SetCCache(ticketCCache); err != nil {
			logger.Warn(fmt.Sprintf("Error setting ccache: %s", err))
			os.Exit(1)
		}
	}
	if len(ticketKirbi) > 0 {
		if err := creds.SetKirbi(ticketKirbi); err != nil {
			logger.Warn(fmt.Sprintf("Error setting kirbi: %s", err))
			os.Exit(1)
		}
	}
	if len(ticketCCache) > 0 || len(ticketKirbi) > 0 {
		if !useKerberos {
			logger.Debug("A Kerberos ticket was supplied, enabling Kerberos authentication")
			useKerberos = true
		}
	}
	cfg.Credentials = creds
	cfg.Network.LDAP.UseKerberos = useKerberos

	// Active Directory registers the ldap service principal name under the domain
	// controller's FQDN, so a Kerberos bind that builds the SPN from an IP address is
	// rejected with KDC_ERR_S_PRINCIPAL_UNKNOWN. Saying so up front beats leaving the
	// caller to decode that error.
	if useKerberos && dcHost == "" && net.ParseIP(domainController) != nil {
		logger.Warn(fmt.Sprintf("Kerberos was requested against the IP address %s: pass --dc-host with the FQDN of the domain controller, or the KDC will reject the service principal name.", domainController))
	}

	switch mode {
	case "monitor":
		// A delay of zero would read the domain controller in a tight loop, which is
		// both useless (an enumeration already takes longer than that) and loud.
		if timeDelay < 1 {
			logger.Warn(fmt.Sprintf("A delay of %d seconds is not usable, falling back to 1 second.", timeDelay))
			cfg.Monitoring.TimeDelay = 1
		}
		if err := mode_monitor.Run(cfg); err != nil {
			logger.Warn(fmt.Sprintf("Error in monitor mode: %s", err))
			os.Exit(1)
		}

	case "snapshot":
		if err := mode_snapshot.Run(cfg); err != nil {
			logger.Warn(fmt.Sprintf("Error in snapshot mode: %s", err))
			os.Exit(1)
		}

	default:
		logger.Warn(fmt.Sprintf("Invalid mode '%s'.", mode))
		os.Exit(1)
	}

	logger.Print("Done.")
}
