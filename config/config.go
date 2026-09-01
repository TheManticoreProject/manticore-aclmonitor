// Package config holds the parsed options of a run, grouped so a mode receives one
// value instead of two dozen positional parameters.
package config

import (
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/manticore-aclmonitor/acls"
)

// Config is the whole configuration of a run. A mode reads the parts that apply to
// it: diff mode never looks at Network or Credentials, and only snapshot mode looks
// at OutputFile.
type Config struct {
	// General
	Debug bool
	// Version of the tool, recorded in a written snapshot so that a file can be
	// traced back to the build that produced it.
	Version string
	// Credentials
	Credentials *credentials.Credentials
	// Network
	Network Network
	// SearchBase is the distinguished name the operator asked to read, as typed.
	// Empty means every naming context. It is resolved into Scope.SearchBases once
	// the session is up.
	SearchBase string
	// Scope is what to read from the directory.
	Scope acls.Scope
	// IgnoreInherited drops the inherited ACEs before comparing two readings. It is
	// not a display filter: it changes which entries are compared at all.
	IgnoreInherited bool
	// Monitoring is how the loop of monitor mode behaves.
	Monitoring Monitoring
	// Reporting is what the operator asked to be shown out of what changed.
	Reporting acls.Reporting
	// ShowSDDL adds the SDDL of a changed descriptor to the output.
	ShowSDDL bool
	// OutputFile is where snapshot mode writes its reading.
	OutputFile string
	// BeforeFile and AfterFile are the two readings diff mode compares.
	BeforeFile string
	AfterFile  string
}

// LDAP holds the LDAP transport and bind options.
type LDAP struct {
	UseLdaps    bool
	UseKerberos bool
	// UseSealing requests the GSSAPI confidentiality layer for a Kerberos bind
	// instead of the integrity layer that is negotiated by default.
	UseSealing bool
	LDAPPort   int
	// SPNHostname overrides the hostname used to build the Kerberos ldap SPN when
	// the domain controller is reached by IP. Empty means use the connection host.
	SPNHostname string
}

// Network holds where to connect and as whom.
type Network struct {
	LDAP             LDAP
	DomainController string
	Domain           string
}

// Monitoring holds how often to read the directory again.
type Monitoring struct {
	// TimeDelay is the number of seconds to wait between two readings.
	TimeDelay int
	// RandomizeDelay picks a random delay between 1 and 5 seconds before each
	// reading instead of using TimeDelay.
	RandomizeDelay bool
}
