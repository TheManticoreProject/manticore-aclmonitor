// Package cli holds the command line helpers of the tool: the interactive prompts.
//
// A tool must never require the password on the command line: anything in argv is
// readable by every local user through the process list, and lands in the shell
// history. The secret flags are optional and ResolvePassword asks for a password on
// the terminal when a run supplied none.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"golang.org/x/term"
)

// ResolvePassword fills in the password by asking for it when no secret was supplied.
//
// Parameters:
//
//	authDomain (string): The domain of the identity, shown in the prompt, may be empty.
//	authUsername (string): The user the password is for, shown in the prompt.
//	authPassword (*string): The password flag, written to when the prompt is used.
//	authNoPass (bool): When true, no prompt happens and no password is set.
//	otherSecrets (...string): Any other secret the tool accepts, such as NT hashes, an
//	  AES key or the path to a ticket. A non-empty one suppresses the prompt.
//
// Returns:
//
//	An error if the password could not be read, or if the caller supplied an empty one,
//	nil otherwise.
func ResolvePassword(authDomain string, authUsername string, authPassword *string, authNoPass bool, otherSecrets ...string) error {
	if *authPassword != "" {
		return nil
	}
	for _, secret := range otherSecrets {
		if secret != "" {
			return nil
		}
	}

	// --no-pass states that the run is meant to happen without a password, so there
	// is nothing to ask for. Whether that is usable is the caller's business.
	if authNoPass {
		return nil
	}

	password, err := PromptForPassword(authDomain, authUsername)
	if err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("no password provided, pass --no-pass to bind without one")
	}

	*authPassword = password
	return nil
}

// PromptForPassword asks for a password on the terminal.
//
// The password is read without echo when the input is a terminal. When it is not, the
// input is read as a plain line instead, so that a password can still be piped in by a
// script, and the caller is told the input was not hidden.
//
// Parameters:
//
//	authDomain (string): The domain of the identity the password is for, may be empty.
//	authUsername (string): The user the password is for.
//
// Returns:
//
//	The password, or an error if it could not be read.
func PromptForPassword(authDomain string, authUsername string) (string, error) {
	identity := authUsername
	if authDomain != "" {
		identity = fmt.Sprintf("%s\\%s", authDomain, authUsername)
	}

	// The prompt is written straight to stderr rather than through the logger: it has
	// to stay on its own line, without a timestamp in front of it, and it does not
	// belong in the log file.
	fmt.Fprintf(os.Stderr, "  | Password for '%s': ", identity)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("error reading the password: %w", err)
		}
		return string(password), nil
	}

	fmt.Fprintln(os.Stderr)
	logger.Debug("The input is not a terminal, reading the password from stdin without hiding it")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("error reading the password: %w", err)
		}
		return "", fmt.Errorf("no password on stdin")
	}

	// A password is taken as typed, apart from the line ending that carried it.
	return strings.TrimRight(scanner.Text(), "\r\n"), nil
}
