// Package mode_monitor watches the security descriptors of a domain and reports what
// changes in them, until the process is interrupted.
package mode_monitor

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-aclmonitor/cli"
)

// SetupSubParser registers the monitor mode and the argument groups it carries.
//
// Parameters:
//
//	ap (*parser.ArgumentsParser): The top-level parser to register the mode on.
//	flags (*cli.Flags): The flag storage to bind to.
func SetupSubParser(ap *parser.ArgumentsParser, flags *cli.Flags) {
	subparser := ap.AddSubParser("monitor", "Watch the security descriptors of a domain and report every change as it happens.")

	cli.RegisterConnectionGroups(subparser, flags)
	cli.RegisterScopeGroup(subparser, flags.SearchBase, flags.LDAPFilter, flags.IncludeSacl)

	// A fixed delay and a randomized one are two answers to the same question, and
	// the randomized one wins when both are set. Making them exclusive says so up
	// front, instead of silently reading every 1 to 5 seconds for a caller who asked
	// for one reading a minute.
	if group, err := subparser.NewNotRequiredMutuallyExclusiveArgumentGroup("Query delay"); err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group.NewIntArgument(flags.TimeDelay, "-t", "--time-delay", 1, false, "Delay between two readings, in seconds.")
		group.NewBoolArgument(flags.RandomizeDelay, "-r", "--randomize-delay", false, "Randomize the delay between two readings, between 1 and 5 seconds.")
	}

	cli.RegisterReportingGroup(subparser, flags.IgnoreInherited, flags.OnlyNotable, flags.Trustee, flags.ShowSddl)
}
