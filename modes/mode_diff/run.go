package mode_diff

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"

	"github.com/TheManticoreProject/manticore-aclmonitor/acls"
	"github.com/TheManticoreProject/manticore-aclmonitor/config"
)

// Run compares two readings taken by snapshot mode.
//
// Parameters:
//
//	cfg (config.Config): The configuration of the run.
//
// Returns:
//
//	An error if either file could not be read.
func Run(cfg config.Config) error {
	before, err := acls.ReadSnapshot(cfg.BeforeFile)
	if err != nil {
		return err
	}
	after, err := acls.ReadSnapshot(cfg.AfterFile)
	if err != nil {
		return err
	}

	logger.Print(fmt.Sprintf("[>] Comparing \x1b[94m%s\x1b[0m (\x1b[93m%d\x1b[0m objects, taken %s) with \x1b[94m%s\x1b[0m (\x1b[93m%d\x1b[0m objects, taken %s).",
		acls.FormatText(cfg.BeforeFile), len(before.Objects), before.TakenAt.Format("2006-01-02 15:04:05 UTC"),
		acls.FormatText(cfg.AfterFile), len(after.Objects), after.TakenAt.Format("2006-01-02 15:04:05 UTC")))

	// An object that one reading never looked at is absent from it, and absent is
	// what a deleted object looks like. Saying so beats reporting the whole
	// difference in scope as objects disappearing and leaving the operator to work
	// out why.
	for _, difference := range acls.ScopeMismatch(before, after) {
		logger.Warn(fmt.Sprintf("The two readings do not cover the same ground: %s. Objects that only one of them read will be reported as appearing or disappearing.", difference))
	}

	// The identity index of the newer reading names the trustees. There is no session
	// to fall back to, which is the point of this mode: a SID that neither reading
	// saw is shown as a SID.
	resolver := acls.NewResolver(after.Snapshot(), after.Domain, nil, nil)

	diffOptions := acls.DiffOptions{
		IgnoreInherited: cfg.IgnoreInherited,
		IncludeSACL:     before.Scope.IncludeSACL && after.Scope.IncludeSACL,
	}
	renderOptions := acls.RenderOptions{ShowSDDL: cfg.ShowSDDL}

	changes := acls.FilterChanges(acls.Diff(before.Snapshot(), after.Snapshot(), diffOptions), cfg.Reporting, resolver)

	logger.Print(fmt.Sprintf("[>] Security descriptor changes (\x1b[93m%d\x1b[0m):", len(changes)))
	for _, change := range changes {
		acls.Render(change, resolver, renderOptions)
	}

	return nil
}
