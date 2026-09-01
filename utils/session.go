// Package utils holds the helpers shared between the modes that talk to a domain
// controller: opening the session, and working out what to read.
package utils

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/manticore-aclmonitor/config"
)

// NewSession creates the LDAP session and binds it to the domain controller.
//
// Parameters:
//
//	cfg (config.Config): The configuration of the run.
//
// Returns:
//
//	A connected LDAP session, or an error if the session could not be created or
//	bound.
func NewSession(cfg config.Config) (*ldap.Session, error) {
	ldapSession, err := ldap.NewSession(
		cfg.Network.DomainController,
		cfg.Network.LDAP.LDAPPort,
		cfg.Credentials,
		cfg.Network.LDAP.UseLdaps,
		cfg.Network.LDAP.UseKerberos,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating LDAP session: %w", err)
	}

	// A Kerberos bind to a domain controller named by IP needs the FQDN in the SPN.
	// Set before connecting; it is a no-op for the non-Kerberos and empty cases.
	if cfg.Network.LDAP.UseKerberos && cfg.Network.LDAP.SPNHostname != "" {
		ldapSession.SetKerberosSPNHostname(cfg.Network.LDAP.SPNHostname)
	}

	// A domain controller that enforces LDAP signing rejects a Kerberos bind that
	// negotiates no security layer, which is what a current Windows Server does by
	// default. So a security layer is negotiated on plain LDAP, and not over LDAPS,
	// where the TLS channel already protects the connection and Active Directory
	// refuses a SASL layer stacked on top of it.
	if cfg.Network.LDAP.UseKerberos && !cfg.Network.LDAP.UseLdaps {
		if cfg.Network.LDAP.UseSealing {
			ldapSession.SetGSSAPISealing()
		} else {
			ldapSession.SetGSSAPISigning()
		}
	}

	// Connect already names the server and the transport in its error, so it is
	// returned as-is rather than wrapped into the same sentence twice.
	connected, err := ldapSession.Connect()
	if err != nil {
		return nil, err
	}
	if !connected {
		return nil, fmt.Errorf("error connecting to LDAP server")
	}

	return ldapSession, nil
}

// AnnounceConnection prints what the run connected to and as whom.
//
// Parameters:
//
//	cfg (config.Config): The configuration of the run.
func AnnounceConnection(cfg config.Config) {
	scheme := "ldap"
	if cfg.Network.LDAP.UseLdaps {
		scheme = "ldaps"
	}
	logger.Print(fmt.Sprintf("[>] Connecting to %s://%s:%d ...", scheme, cfg.Network.DomainController, cfg.Network.LDAP.LDAPPort))
}

// AnnounceIdentity prints whether the bind authenticated or not.
//
// A bind with no secret succeeds against a domain controller as an anonymous one, so
// the message has to say which of the two happened rather than claim an
// authentication that did not take place.
//
// Parameters:
//
//	creds (*credentials.Credentials): The credentials the session was built with.
func AnnounceIdentity(creds *credentials.Credentials) {
	if HasSecret(creds) {
		logger.Print(fmt.Sprintf("[+] Authenticated as \x1b[94m%s\\%s\x1b[0m.", creds.GetDomain(), creds.GetUsername()))
		return
	}
	logger.Print(fmt.Sprintf("[+] Bound without authentication as \x1b[94m%s\x1b[0m.", creds.GetUsername()))
}

// HasSecret reports whether the credentials carry anything to authenticate with.
//
// Parameters:
//
//	creds (*credentials.Credentials): The credentials the session was built with.
//
// Returns:
//
//	True when a secret was supplied, false otherwise.
func HasSecret(creds *credentials.Credentials) bool {
	return creds.GetPassword() != "" ||
		creds.CanPassTheHash() ||
		creds.CanUseAESKey() ||
		creds.CanUseCCache() ||
		creds.CanUseKirbi() ||
		creds.CanUseKeytab()
}

// ResolveSearchBases determines what to read: the search base the caller asked for,
// or every naming context the domain controller advertises.
//
// Parameters:
//
//	ldapSession (*ldap.Session): The connected LDAP session to query.
//	searchBase (string): The distinguished name to read, or empty for all naming contexts.
//
// Returns:
//
//	The distinguished names to read, or an error if the requested search base does not
//	exist or the naming contexts could not be read.
func ResolveSearchBases(ldapSession *ldap.Session, searchBase string) ([]string, error) {
	searchBase = strings.TrimSpace(searchBase)

	if searchBase == "" {
		namingContexts, err := ldapSession.GetAllNamingContexts()
		if err != nil {
			return nil, fmt.Errorf("error fetching the naming contexts: %w", err)
		}
		return namingContexts, nil
	}

	// A search base that does not exist yields an empty reading and a run that
	// silently reports nothing forever, so it is rejected up front.
	exists, err := ldapSession.DistinguishedNameExists(searchBase)
	if err != nil {
		return nil, fmt.Errorf("error checking search base '%s': %w", searchBase, err)
	}
	if !exists {
		return nil, fmt.Errorf("search base '%s' does not exist", searchBase)
	}

	return []string{searchBase}, nil
}

// AnnounceSearchBases prints what the run is going to read.
//
// Parameters:
//
//	searchBases ([]string): The distinguished names to read.
func AnnounceSearchBases(searchBases []string) {
	logger.Print(fmt.Sprintf("[>] Search bases (\x1b[93m%d\x1b[0m):", len(searchBases)))
	for index, searchBase := range searchBases {
		branch := "  ├── "
		if index == len(searchBases)-1 {
			branch = "  └── "
		}
		logger.Plain.Print(fmt.Sprintf("%s\x1b[94m%s\x1b[0m", branch, searchBase))
	}
}
