# PS-Script-Redactor
Python GUI tool to redact PowerShell scripts.

Paste or open a script, and a redacted copy appears below it with every replacement highlighted. 37 detectors cover secrets, tenant IDs, accounts, hostnames and paths; you add your own company names and terms on top.

![Main window](screenshots/main-window.PNG)

---

## Requirements

- Python 3.8 or newer
- tkinter (bundled with Python on Windows and macOS; `sudo apt install python3-tk` on Debian/Ubuntu)

No third-party packages. No network access. Nothing leaves your machine.

## Running it

```bash
python ps_redactor.py
```

The whole tool is one file. Copy it wherever you like.

## Using it

1. **Open file…** to load a `.ps1`, or click into the top box and paste.
2. The redacted version builds itself in the lower box about a third of a second after you stop typing.
3. Walk the ▲ ▼ arrows next to the redaction count to review every replacement, one at a time. `F3` and `Shift+F3` do the same.
4. **Copy redacted text** or **Export to file…** (`Ctrl+S`).

![Redaction navigation](screenshots/navigation.PNG)

### Placeholders

Redactions are labelled by what was found: `<TENANT ID>`, `<EMAIL ADDRESS>`, `<UNC PATH>`.

The same value always gets the same placeholder, so relationships in the script survive redaction — a reader can still see that the mailbox being granted access is the one logged three lines later. Numbers only appear when a label has more than one distinct value:

```powershell
# before
$owner  = "alice@corp.com"
$backup = "bob@corp.com"
Add-MailboxPermission -User "alice@corp.com"

# after
$owner  = "<EMAIL ADDRESS 1>"
$backup = "<EMAIL ADDRESS 2>"
Add-MailboxPermission -User "<EMAIL ADDRESS 1>"
```

Matching is case-insensitive, so `Alice@corp.com` and `alice@corp.com` count as one value.

## Settings

![Settings](screenshots/settings.PNG)

### Company names and terms

One per line. Company names are caught on their own and inside URLs and hostnames. The **Other terms** box is for anything else that identifies you — project names, server names, group names, internal app names.

This box is the backstop for values nothing else can detect. A server called `PRDSQL04` has no structure to recognise; put it here once and it's redacted in every script from then on.

### Allow list

Substring matches that are never redacted, on token boundaries. Ships with the public endpoints that appear in nearly every M365 script and identify nobody: `graph.microsoft.com`, `login.microsoftonline.com`, `outlook.office365.com`, `powershellgallery.com`, `127.0.0.1`, `::1` and similar.

Without it, every `Invoke-MgGraphRequest` call would read `<URL>` and the script would be unreadable for no security gain.

The allow list never overrides your own company names, terms or custom patterns.

### Custom patterns

One per line, `LABEL = regex`:

```
EMPLOYEE ID = EMP\d{6}
TICKET = (INC|REQ)\d{7}
```

Invalid regexes are reported and skipped rather than silently ignored.

### Options

| Option | Default | Effect |
| --- | --- | --- |
| Number placeholders when there is more than one value | on | `<USERNAME 1>` / `<USERNAME 2>` vs a flat `<USERNAME>` |
| Redact private IP ranges | on | Off keeps `10.x`, `192.168.x`, `172.16–31.x`, `127.x` in place |
| Match company names / terms inside longer words | off | On catches `contosoprod01`; also catches false positives |
| Redact a found username everywhere else in the script | on | See below |
| PowerShell syntax highlighting in both boxes | on | |

## How usernames are found

A bare word like `clance` has no shape that distinguishes it from any other word, so it's found by context instead:

- **The variable name.** Any variable containing `user`, `account`, `upn`, `samaccountname`, `identity`, `mailbox`, `owner`, `manager`, `member`, `admin`, `employee`, `person`, `alias`, `displayname`, `login`, `logon` or `recipient`, with a quoted value. `$targetUser`, `$svcAccount`, `$mailboxOwner`, `$UserList` all qualify — including every element of an array.
- **The parameter name.** A quoted value passed to `-Identity`, `-SamAccountName`, `-UserPrincipalName`, `-Mailbox`, `-Members`, `-Owner`, `-Manager`, `-GroupName`, `-DisplayName`, `-Alias` and about a dozen others.
- **Then it spreads.** Once a value has been identified as an account anywhere in the script, every other occurrence of that exact string is redacted too — in comments, in `Write-Host` output, anywhere.

```powershell
# before
$targetUser = "clance"
Get-ADUser -Identity "clance"
Write-Host "Removing clance from Test-Account"

# after
$targetUser = "<USERNAME 1>"
Get-ADUser -Identity "<USERNAME 1>"
Write-Host "Removing <USERNAME 1> from <USERNAME 2>"
```

`Test-Account` is caught because it appeared as a `-Identity` value earlier in the same script. A name that never appears in an account position anywhere goes in the terms list instead.

## Detectors

All toggleable. The first four groups are on by default.

### Secrets and keys

| Detects | Placeholder |
| --- | --- |
| `-----BEGIN PRIVATE KEY-----` blocks | `<PRIVATE KEY>` |
| `-----BEGIN CERTIFICATE-----` blocks | `<CERTIFICATE>` |
| JWT / bearer tokens (`eyJ…`) | `<JWT TOKEN>` |
| Azure AD / Entra client secrets | `<CLIENT SECRET>` |
| AWS, GitHub, Slack, Stripe, Google, OpenAI, GitLab, npm key formats | `<API KEY>` |
| Quoted values assigned to secret-looking variables (`$apiKey = "…"`) | `<SECRET>` |
| Quoted values on `-Password`, `-ClientSecret`, `-Token` etc. | `<SECRET>` |
| `ConvertTo-SecureString` plain text | `<SECRET>` |
| Connection strings (`Server=…;Database=…;`) | `<CONNECTION STRING>` |
| Certificate thumbprints | `<CERT THUMBPRINT>` |
| Base64 blobs, 40+ chars | `<ENCODED DATA>` |
| Hex strings, 32+ chars | `<HEX STRING>` |

### Microsoft 365 and Azure

| Detects | Placeholder |
| --- | --- |
| SharePoint Online / OneDrive URLs | `<SHAREPOINT URL>` |
| `*.onmicrosoft.com` | `<TENANT DOMAIN>` |
| `*.mail.protection.outlook.com` | `<EXCHANGE ENDPOINT>` |
| GUIDs, labelled from surrounding context | `<TENANT ID>`, `<APP ID>`, `<SUBSCRIPTION ID>`, `<OBJECT ID>`, `<GUID>` |

### Identity and accounts

| Detects | Placeholder |
| --- | --- |
| Email addresses and UPNs | `<EMAIL ADDRESS>` |
| LDAP distinguished names | `<DISTINGUISHED NAME>` |
| Windows SIDs | `<SID>` |
| `DOMAIN\username` | `<DOMAIN USER>` |
| `C:\Users\jsmith` | `<USER PROFILE PATH>` |
| Account-looking variables and parameters | `<USERNAME>` |
| Phone numbers | `<PHONE NUMBER>` |

### Network and infrastructure

| Detects | Placeholder |
| --- | --- |
| UNC paths | `<UNC PATH>` |
| `*.local`, `*.corp`, `*.internal`, `*.lan`, `*.ad`, `*.dmz` etc. | `<INTERNAL HOSTNAME>` |
| IPv4, including compressed IPv6 | `<IP ADDRESS>`, `<IPV6 ADDRESS>` |
| MAC addresses | `<MAC ADDRESS>` |
| URLs not on the allow list | `<URL>` |

### Scrub everything — off by default

For when you'd rather destroy a readable script than risk a miss.

| Detects | Placeholder |
| --- | --- |
| Every quoted value assigned to any variable | `<STRING>` |
| Quoted text given to `Write-Host`, `Read-Host`, logging cmdlets | `<TEXT>` |
| Every quoted string anywhere, single or double | `<STRING>` |
| Any file or folder path | `<PATH>` |
| Anything dotted that looks like a hostname, whatever the suffix | `<HOSTNAME>` |
| Server-style names: caps and digits, e.g. `PRDSQL04`, `DC01` | `<ASSET NAME>` |
| Whole comments, block comments included | `<COMMENT>` |

The comments one is the highest-value of these for real scripts. Comments are where server names, ticket numbers and colleagues' names sit in prose that no structural pattern will ever catch.

![Aggressive mode](screenshots/aggressive.PNG)

## Where settings are stored

In the script file itself, in a JSON block between the `SETTINGS_BEGIN` and `SETTINGS_END` markers, rewritten atomically when you press Save. The file stays a single portable artifact — copy it to another machine and your company names and toggles come with it.

If the file is read-only, or you've frozen it with PyInstaller, it falls back to `ps_redactor.settings.json` next to the executable and tells you it did.

## Limitations

Read this part.

**It can miss things.** Pattern matching finds what has recognisable structure. `$server = "PRDSQL04"` has none — no domain suffix, no format, nothing. It is not detected by default, and nothing tells you it was missed. This is the failure mode that matters, because it's silent.

**Some detectors over-match.** Base64 blobs, long hex strings and phone numbers guess from shape and will occasionally redact something harmless. That's the safe direction, and they're individually toggleable.

**The context-based detectors depend on naming.** Usernames and secrets are found through variable and parameter names. Unconventional naming gets missed.

**So review the output.** The ▼ arrow exists for exactly this. Walk every redaction, read what's left in plaintext, and ask whether any of it is yours. Anything that gets missed belongs in the terms list, where it's caught permanently from then on.

This tool reduces the manual work of redaction. It does not replace reading your own script before you publish it.

## About this code

Built with Claude (Anthropic) across an iterative session — described, tested, corrected, rebuilt. I directed the design and requirements; the implementation is largely model-written, and I'm not going to pretend otherwise.

That's relevant to you as a reader for one reason: **read the detector regexes before you trust them with anything sensitive.** They're all in `DETECTOR_SPECS` near the top of the file, each with a plain-English label next to it. Several bugs were found and fixed by testing each detector in isolation — IPv6 not matching compressed addresses, the allow list matching substrings across token boundaries, variable-name patterns failing when the keyword started the name. There may be more.

## License

MIT
