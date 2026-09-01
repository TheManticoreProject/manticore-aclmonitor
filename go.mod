module github.com/TheManticoreProject/manticore-aclmonitor

go 1.24.0

require (
	github.com/TheManticoreProject/Manticore v1.1.6
	github.com/TheManticoreProject/goopts v1.2.4
	github.com/TheManticoreProject/winacl v1.3.2
	github.com/go-ldap/ldap/v3 v3.4.12
	golang.org/x/term v0.36.0
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

// Local Manticore checkout, for iterating on library changes without waiting for a
// release. Disabled by default: it must not be committed active, since the path
// does not exist for anyone installing this tool, and pointing it at a branch that
// predates a needed library change silently builds against the older code.
//
// Enable it only once ../Manticore contains the commit named in the require above.
// replace github.com/TheManticoreProject/Manticore => ../Manticore

// Local winacl checkout, for iterating on library changes without waiting for a
// release. Disabled by default, for the same reason as the Manticore replace above.
//
// Enable it only once ../winacl contains the commit named in the require above.
// replace github.com/TheManticoreProject/winacl => ../winacl
