![](./.github/banner.png)

<p align="center">
      A tool to watch, diff and report the live changes of the Windows security descriptors of Active Directory objects over LDAP
      <br>
      <a href="https://github.com/TheManticoreProject/manticore-aclmonitor/actions/workflows/release.yaml" title="Build"><img alt="Build and Release" src="https://github.com/TheManticoreProject/manticore-aclmonitor/actions/workflows/release.yaml/badge.svg"></a>
      <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/TheManticoreProject/manticore-aclmonitor">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/TheManticoreProject/manticore-aclmonitor">
      <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
      <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
      <br>
</p>

## Features

- [x] Watch every naming context of a domain live, or a single subtree with `--search-base`
- [x] ACEs reported as added, removed, or re-masked, with the rights that were granted and revoked on an existing entry shown individually
- [x] Rights rendered as what they let somebody do: DCSync, shadow credentials, resource-based constrained delegation, targeted kerberoasting, force-change-password, add-members-to-this-group, WriteDacl, WriteOwner, full control
- [x] Owner and group changes, which no ACE records
- [x] Inheritance being broken (`SE_DACL_PROTECTED`) reported in those words
- [x] An empty DACL told apart from an absent one: one denies everyone everything, the other grants everyone full control
- [x] Trustee SIDs resolved to names, from the enumeration the tool is already doing, at no extra cost
- [x] `snapshot` and `diff` modes: capture on the engagement host, analyse anywhere, with no domain controller and no credentials needed to compare two captures
- [x] Cut the noise with `--only-notable`, `--trustee`, `--ignore-inherited` and `--ldap-filter`
- [x] SDDL of both sides of a change with `--sddl`
- [x] SACL monitoring with `--include-sacl`, for a run that holds `SeSecurityPrivilege`
- [x] Password asked for on the terminal when none is given, so the secret never has to go in the command line
- [x] LDAP, or LDAPS with `--use-ldaps`, and a signed or encrypted Kerberos session on plain LDAP for a domain controller that enforces LDAP signing
- [x] Authenticate with a password (`-p`), an NT hash (`-H`), an AES key (`--aes-key`) or a Kerberos ticket (`--ticket-ccache`, `--ticket-kirbi`), over Kerberos (`-k`) or NTLM
- [x] Reconnect and carry on when the domain controller drops a long-running session
- [x] Escape sequences in distinguished names and in resolved account names neutralized before they reach the terminal
- [x] Colored output, or plain text with `--no-colors`, and a log file with `--logfile`
- [ ] Report a DACL that has fallen out of canonical order
- [ ] Diff a stored capture directly against a live domain, without taking a second capture first

## Installation

Download the latest release from the [GitHub release page](https://github.com/TheManticoreProject/manticore-aclmonitor/releases), or install it with:

```bash
go install github.com/TheManticoreProject/manticore-aclmonitor@latest
```

## Usage

```
$ ./manticore-aclmonitor
manticore-aclmonitor - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: manticore-aclmonitor <diff|monitor|snapshot>

   diff      Compare two readings taken by snapshot mode, with no domain controller in reach.
   monitor   Watch the security descriptors of a domain and report every change as it happens.
   snapshot  Read the security descriptors of a domain once and write them to a file.
```

At most one of the `Secret` options may be given, and none is needed on the command
line: the password is asked for on the terminal when it is missing, which keeps it out
of `argv`, where the process list exposes it to every local user, and out of the shell
history. It is read from standard input when that is not a terminal, so a script can
pipe it in.

A domain controller that enforces LDAP signing, the default on a current Windows
Server, answers a password or hash bind on plain LDAP with `LDAP Result Code 8
"Strong Auth Required"`. Either add `--use-ldaps`, or authenticate with Kerberos
(`-k`), which signs the session on plain LDAP so the domain controller accepts it. Add
`--use-sealing` to encrypt it rather than only signing it.

### Watch a domain live

A real session against a lab domain controller, watching one container while an ACL is
edited underneath it:

```
$ ./manticore-aclmonitor monitor -d TMP-W-2025.local -u Administrator -dc 10.7.0.13 -L \
    -S 'CN=Users,DC=TMP-W-2025,DC=local' -t 3 --ignore-inherited
manticore-aclmonitor - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

  | Password for 'TMP-W-2025.local\Administrator':
[2026-09-01 12h35m14s] [>] Connecting to ldaps://10.7.0.13:636 ...
[2026-09-01 12h35m14s] [+] Authenticated as TMP-W-2025.local\Administrator.
[2026-09-01 12h35m14s] [>] Search bases (1):
  └── CN=Users,DC=TMP-W-2025,DC=local
[2026-09-01 12h35m14s] [>] Security descriptors in the initial reading: 33.
[2026-09-01 12h35m14s] [>] Listening for security descriptor changes ...
[2026-09-01 12h35m53s] [~] Security descriptor changed: CN=aclmon-target,CN=Users,DC=TMP-W-2025,DC=local
  ├── [+] DACL ACE added: Allow TMP-W-2025.local\kctest1 (S-1-5-21-616114433-2894206284-1395970530-1195)
  │   └── + Can read every attribute of the object
  └── The directory recorded the write at 2026-09-01 10:35:51 UTC
[2026-09-01 12h36m05s] [~] Security descriptor changed: CN=aclmon-target,CN=Users,DC=TMP-W-2025,DC=local
  ├── [~] DACL ACE changed: Allow TMP-W-2025.local\kctest1 (S-1-5-21-616114433-2894206284-1395970530-1195)
  │   ├── + Can rewrite the ACL of the object (WriteDacl)
  │   ├── + Can take ownership of the object (WriteOwner)
  │   └── - Can read every attribute of the object
  └── The directory recorded the write at 2026-09-01 10:36:03 UTC
```

The second event is the one a generic directory monitor cannot give you. The ACE was
not removed and replaced: it is the same entry against the same trustee, and what
moved is the mask. The rights that were granted and the right that was taken away are
reported individually, on the entry they moved on.

The password was not passed on the command line. It was asked for on the terminal, and
`-p` is there for a script that has nowhere to type it.

### Inheritance, and the storm it causes

Breaking inheritance on an object is a single flag in the descriptor, and no ACE
records it. It is reported in those words, alongside everything the domain controller
then stopped applying to the object:

```
[2026-09-01 12h31m42s] [~] Security descriptor changed: CN=aclmon-target,CN=Users,DC=TMP-W-2025,DC=local
  ├── Inheritance was broken: the object no longer receives the ACEs of its parent (SE_DACL_PROTECTED set)
  ├── [+] DACL ACE added: Allow TMP-W-2025.local\aclmon-probe (S-1-5-21-616114433-2894206284-1395970530-1204)
  │   └── + Shadow credentials: can add a key credential and authenticate as this account
  ├── [-] DACL ACE removed: Allow TMP-W-2025.local\Key Admins (S-1-5-21-616114433-2894206284-1395970530-526) [CONTAINER_INHERIT, INHERITED]
  │   ├── - DS_READ_PROPERTY on LDAP Attribute: ms-ds-key-credential-link
  │   └── - Shadow credentials: can add a key credential and authenticate as this account
  ├── [-] DACL ACE removed: Allow Principal Self (S-1-5-10) [OBJECT_INHERIT, CONTAINER_INHERIT, INHERITED]
  │   ├── - DS_READ_PROPERTY on LDAP Attribute: ms-ds-allowed-to-act-on-behalf-of-other-identity
  │   └── - Resource-based constrained delegation: can let another account impersonate anyone to this one
  ├── [-] DACL ACE removed: Allow BUILTIN\Administrators (S-1-5-32-544) [CONTAINER_INHERIT, INHERITED]
  │   ├── - Can create child objects of any class
  │   ├── - Can perform every validated write on the object
  │   ├── - Can read every attribute of the object
  │   ├── - Can write every attribute of the object
  │   ├── - Holds every extended right on the object
  │   ├── - Can delete the object
  │   ├── - Can read the ACL of the object
  │   ├── - Can rewrite the ACL of the object (WriteDacl)
  │   └── - Can take ownership of the object (WriteOwner)
  │
  │   ... 19 further inherited ACEs, elided here for length
  │
  └── The directory recorded the write at 2026-09-01 10:31:39 UTC
```

Twenty-two inherited ACEs stopped applying because of one flag. That is what happened
and it is worth seeing once, but it buries the one line that matters. `--ignore-inherited`
drops the inherited entries and leaves the write itself, which is why the session above
was run with it.

### Capture now, compare later

`snapshot` writes one reading to a file and exits. `diff` compares two of them and
needs neither a domain controller nor credentials, so the capture can happen on the
engagement host and the analysis somewhere else entirely.

```
$ ./manticore-aclmonitor snapshot -d TMP-W-2025.local -u Administrator -dc 10.7.0.13 -L \
    -o before.aclsnapshot.gz
manticore-aclmonitor - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

[2026-09-01 12h28m07s] [>] Connecting to ldaps://10.7.0.13:636 ...
[2026-09-01 12h28m07s] [+] Authenticated as TMP-W-2025.local\Administrator.
[2026-09-01 12h28m07s] [>] Search bases (5):
  ├── DC=TMP-W-2025,DC=local
  ├── CN=Configuration,DC=TMP-W-2025,DC=local
  ├── CN=Schema,CN=Configuration,DC=TMP-W-2025,DC=local
  ├── DC=DomainDnsZones,DC=TMP-W-2025,DC=local
  └── DC=ForestDnsZones,DC=TMP-W-2025,DC=local
[2026-09-01 12h28m07s] [>] Security descriptors read: 3689.
[2026-09-01 12h28m07s] [+] Reading written to before.aclsnapshot.gz.
[2026-09-01 12h28m07s] Done.
```

That is every naming context of the domain, 3689 descriptors, in a 66 KB gzipped file.
Later, with nothing to connect to:

```
$ ./manticore-aclmonitor diff --before before.aclsnapshot.gz --after after.aclsnapshot.gz
manticore-aclmonitor - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

[2026-09-01 12h34m25s] [>] Comparing before.aclsnapshot.gz (3689 objects, taken 2026-09-01 10:28:07 UTC) with after.aclsnapshot.gz (3691 objects, taken 2026-09-01 10:34:25 UTC).
[2026-09-01 12h34m25s] [>] Security descriptor changes (2):
[2026-09-01 12h34m25s] [+] Security descriptor appeared: CN=aclmon-probe,CN=Users,DC=TMP-W-2025,DC=local
[2026-09-01 12h34m25s] [+] Security descriptor appeared: CN=aclmon-target,CN=Users,DC=TMP-W-2025,DC=local
[2026-09-01 12h34m25s] Done.
```

Two objects were created between the readings and nothing else moved, across 3689
descriptors, so that is all it reports. The file carries the SID-to-name index
alongside the descriptors, which is why a trustee still has a name in a comparison run
with nothing to ask. It also carries the scope it was taken with, and `diff` says so
when the two files do not cover the same ground, since an object one of them never
read looks exactly like a deleted one.

### Cut the noise

A change that grants an ordinary read alongside one that hands over an account is
reported in full by default:

```
$ ./manticore-aclmonitor diff --before before.aclsnapshot --after after.aclsnapshot
[2026-09-01 12h38m19s] [>] Security descriptor changes (1):
[2026-09-01 12h38m19s] [~] Security descriptor changed: CN=aclmon-target,CN=Users,DC=TMP-W-2025,DC=local
  ├── [+] DACL ACE added: Allow TMP-W-2025.local\kctest2 (S-1-5-21-616114433-2894206284-1395970530-1196)
  │   └── + Shadow credentials: can add a key credential and authenticate as this account
  ├── [+] DACL ACE added: Allow TMP-W-2025.local\kctest1 (S-1-5-21-616114433-2894206284-1395970530-1195)
  │   └── + Can read the ACL of the object
  └── The directory recorded the write at 2026-09-01 10:38:16 UTC
```

`--only-notable` keeps just the rights that hand somebody control of the object or of
the identity behind it, and drops the read:

```
$ ./manticore-aclmonitor diff --before before.aclsnapshot --after after.aclsnapshot --only-notable
[2026-09-01 12h38m19s] [~] Security descriptor changed: CN=aclmon-target,CN=Users,DC=TMP-W-2025,DC=local
  ├── [+] DACL ACE added: Allow TMP-W-2025.local\kctest2 (S-1-5-21-616114433-2894206284-1395970530-1196)
  │   └── + Shadow credentials: can add a key credential and authenticate as this account
  └── The directory recorded the write at 2026-09-01 10:38:16 UTC
```

`--trustee` answers the other question, what did this principal get, by SID, by name or
by a fragment of either:

```
$ ./manticore-aclmonitor diff --before before.aclsnapshot --after after.aclsnapshot --trustee kctest1
[2026-09-01 12h38m19s] [~] Security descriptor changed: CN=aclmon-target,CN=Users,DC=TMP-W-2025,DC=local
  ├── [+] DACL ACE added: Allow TMP-W-2025.local\kctest1 (S-1-5-21-616114433-2894206284-1395970530-1195)
  │   └── + Can read the ACL of the object
  └── The directory recorded the write at 2026-09-01 10:38:16 UTC
```

`--ignore-inherited` drops the changes to inherited ACEs, which is what makes one write
to a container readable instead of a storm across everything below it.
`--ldap-filter '(objectClass=user)'` narrows what is read in the first place, which is
also what makes the monitor loop tighter.

`--sddl` adds both sides of a changed descriptor, for pasting into another tool:

```
  ├── SDDL
  │   ├── before O:S-1-5-21-...-512G:S-1-5-21-...-512D:AI(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;S-1-5-21-...-553)(...)
  │   └── after  O:S-1-5-21-...-512G:S-1-5-21-...-512D:AI(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;S-1-5-21-...-553)(...)
```

### Options of each mode

```
$ ./manticore-aclmonitor monitor --help
...
  Scope:
    -S, --search-base <string> Distinguished name to read. If omitted, every naming context of the domain controller is read. (default: "")
    -f, --ldap-filter <string> LDAP filter restricting which objects are read. (default: "(objectClass=*)")
    --include-sacl             Also read and compare the SACL. Requires SeSecurityPrivilege: without it the domain controller returns no security descriptor at all. (default: false)

  Query delay:
    -t, --time-delay <int> Delay between two readings, in seconds. (default: 1)
    -r, --randomize-delay  Randomize the delay between two readings, between 1 and 5 seconds. (default: false)

  Reporting:
    --ignore-inherited Do not report changes to inherited ACEs. One write to a container lands on every object below it; this shows the write instead of the storm. (default: false)
    --only-notable     Report only the changes that move a right which hands somebody control of the object or of the identity behind it. (default: false)
    --trustee <string> Report only the ACEs whose trustee matches this SID, name or substring. (default: "")
    --sddl             Also print the SDDL of the descriptor before and after the change. (default: false)
```

## Typical use cases

- Confirm that an ACL-based privilege escalation landed, and see exactly which right it wrote.
- Watch a delegation being set up: `msDS-KeyCredentialLink`, `msDS-AllowedToActOnBehalfOfOtherIdentity` or a `servicePrincipalName` write appearing on an account.
- Catch DCSync being granted on the domain head, in real time.
- Take a capture before an engagement and another after, and hand over exactly what changed in the ACLs of the domain.
- Watch an ACL cleanup and confirm that the rights that were meant to go, went.

## Limitations

A change is found by comparing a full reading of the search bases with the previous
one, so `monitor` reports a change at the first reading that runs after it lands. The
refresh rate is bounded by how long one enumeration takes, not by `--time-delay`: on a
domain with many objects an enumeration takes several seconds on its own, and
`--time-delay` is the pause added on top of it. `--search-base` and `--ldap-filter`
are what make the loop tighter.

Two readings are held at a time, so the memory the tool uses grows with the number of
objects in scope. Descriptors are held as the bytes the server sent and are only
parsed when those bytes move, so a quiet cycle is cheap however large the domain.

Reading the SACL needs `SeSecurityPrivilege`. `--include-sacl` asks the domain
controller for it, and a run that does not hold the privilege gets no security
descriptor at all back, not merely a descriptor without its SACL. That is why the
option is off by default.

LDAP says what changed, never who changed it. The `whenChanged` of the object is
reported alongside each change so it can be correlated with a domain controller's own
event log.

An ACE that removes the monitoring account's own read access makes the object vanish
from the reading, which is reported as its security descriptor disappearing. So is a
deletion. The two are indistinguishable over LDAP, and the wording says so.

`diff` compares what was captured, so a change that landed and was reverted between
two `snapshot` runs is invisible to it. Only `monitor` sees the intermediate states,
and only at its own cycle rate.

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits

  - [p0dalirius](https://github.com/p0dalirius) for [LDAPmonitor](https://github.com/p0dalirius/LDAPmonitor), whose live-diff approach this tool applies to security descriptors, and for the [winacl](https://github.com/TheManticoreProject/winacl) library that parses them.
