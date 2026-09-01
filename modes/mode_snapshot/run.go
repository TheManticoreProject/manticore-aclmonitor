package mode_snapshot

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"

	"github.com/TheManticoreProject/manticore-aclmonitor/acls"
	"github.com/TheManticoreProject/manticore-aclmonitor/config"
	"github.com/TheManticoreProject/manticore-aclmonitor/utils"
)

// Run reads the security descriptors of the domain once and writes them to a file.
//
// The file holds the identity index alongside the descriptors, so that a later diff
// can name the trustees of an ACE with no domain controller in reach, and the scope
// the reading was taken with, so that a diff can say when the two files it was handed
// do not cover the same ground.
//
// Parameters:
//
//	cfg (config.Config): The configuration of the run.
//
// Returns:
//
//	An error if connecting to the domain controller, reading from it, or writing the
//	file failed.
func Run(cfg config.Config) error {
	utils.AnnounceConnection(cfg)

	ldapSession, err := utils.NewSession(cfg)
	if err != nil {
		return err
	}
	defer ldapSession.Close()

	utils.AnnounceIdentity(cfg.Credentials)

	searchBases, err := utils.ResolveSearchBases(ldapSession, cfg.SearchBase)
	if err != nil {
		return err
	}
	cfg.Scope.SearchBases = searchBases
	utils.AnnounceSearchBases(searchBases)

	if cfg.Scope.IncludeSACL {
		logger.Print("[>] The SACL is included in the reading, which needs SeSecurityPrivilege on the domain controller.")
	}

	snapshot, err := acls.TakeSnapshot(ldapSession, cfg.Scope, cfg.Debug)
	if err != nil {
		return err
	}
	logger.Print(fmt.Sprintf("[>] Security descriptors read: \x1b[93m%d\x1b[0m.", len(snapshot.Objects)))

	stored := &acls.StoredSnapshot{
		Version:          cfg.Version,
		Domain:           cfg.Network.Domain,
		DomainController: cfg.Network.DomainController,
		Scope:            cfg.Scope,
		Identities:       snapshot.Identities,
		Objects:          snapshot.Objects,
	}

	if err := acls.WriteSnapshot(cfg.OutputFile, stored); err != nil {
		return err
	}

	logger.Print(fmt.Sprintf("[+] Reading written to \x1b[94m%s\x1b[0m.", acls.FormatText(cfg.OutputFile)))
	return nil
}
