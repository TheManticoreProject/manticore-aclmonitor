// Package mode_diff compares two readings taken by snapshot mode and reports what
// changed between them.
package mode_diff

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-aclmonitor/cli"
)

// SetupSubParser registers the diff mode and the argument groups it carries.
//
// It carries neither the LDAP connection nor the authentication group: comparing two
// files needs no domain controller and no credentials, which is what lets the reading
// happen on the engagement host and the analysis somewhere else.
//
// Parameters:
//
//	ap (*parser.ArgumentsParser): The top-level parser to register the mode on.
//	flags (*cli.Flags): The flag storage to bind to.
func SetupSubParser(ap *parser.ArgumentsParser, flags *cli.Flags) {
	subparser := ap.AddSubParser("diff", "Compare two readings taken by snapshot mode, with no domain controller in reach.")

	cli.RegisterConfigurationGroup(subparser, flags.Debug, flags.NoColors, flags.LogFile)

	if group, err := subparser.NewArgumentGroup("Snapshots"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group.NewStringArgument(flags.BeforeFile, "", "--before", "", true, "The older reading.")
		group.NewStringArgument(flags.AfterFile, "", "--after", "", true, "The newer reading.")
	}

	cli.RegisterReportingGroup(subparser, flags.IgnoreInherited, flags.OnlyNotable, flags.Trustee, flags.ShowSddl)
}
