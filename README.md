# LFI2-Advanced-Local-File-Inclusion---Lab-Report


Educational Security Research Report
 Documenting observed vulnerability behavior, successful bypass techniques, and error analysis.

---

##  Lab Overview

| Property | Detail |
|---|---|
| Lab | LFI2: Advanced Local File Inclusion |
| Difficulty | Advanced |
| Objective | Bypass security filters to read sensitive files |
| Target File | `app_secrets.txt` |
| Flag Captured | `FLAG{local_file_inclusion_master}` |

---

## ✅ Successful Exploit

### Payload Used
```
..\/..\/app_secrets.txt
<div>
<img width="1366" height="688" alt="appl" src="https://github.com/user-attachments/assets/21fb8124-3481-4b5b-b2e4-16f38cdae96a" />
</div>

**Technique:** Mixed separator bypass

The filter blocked `../` but did not account for `..\/` (mixing forward and backslash). The OS path resolver treated `\/` as a valid separator and traversed up the directory tree successfully.

---

## ❌ Error Analysis

### Error 1: `EISDIR: illegal operation on a directory, read`

**Root Cause:**
The traversal payload succeeded in escaping `content/` but resolved to a **directory** rather than a file. Node.js `fs.readFileSync()` cannot read directories.

**What this tells us:** EISDIR confirms path traversal IS working — the attacker just aimed at a folder instead of a file. It's useful reconnaissance.

```js
// What the server tried:
fs.readFileSync("/app/content/")  // ← directory, not a file

// Fix:
if (!fs.statSync(resolved).isFile()) throw new Error('Not a file');
```

---

### Error 2: `ENOENT: no such file or directory`

**Full path in error:**
```
/app/content/%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

**Root Cause — Double encoding not decoded:**
```
Attacker expected (two decode passes):
  %252e → %2e → .
  %252f → %2f → /

Actual server behavior (one decode pass only):
  %252e → %2e   ← stopped here
  OS receives literal: %2e%2e%2f... → ENOENT
```

Double encoding only works if the server decodes **twice**. This server decodes once — the payload never resolved into `../`.

---

##  Bypass Techniques Tested

| Payload | Technique | Result |
|---|---|---|
| `../app_secrets.txt` | Basic traversal | ❌ Blocked |
| `....//....//app_secrets.txt` | Nested string bypass | ❓ Untested |
| `%2e%2e%2fapp_secrets.txt` | Single URL encode | ❓ Untested |
| `%252e%252e%252fetc%252fpasswd` | Double URL encode | ❌ ENOENT |
| `..\/..\/app_secrets.txt` | Mixed separator | ✅ **SUCCESS** |
| Directory path traversal | Any | ❌ EISDIR |

---

##  Filter Weakness Identified

```js
// Vulnerable filter (pseudocode)
filename = filename.replace("../", "");
// Does NOT block: ..\/  ← exploit point
```

---

##  Remediation

### Canonical Path Validation (Most Effective)
```js
const path = require('path');
const SAFE_ROOT = '/app/content';

function safeRead(userInput) {
  const decoded = decodeURIComponent(decodeURIComponent(userInput));
  const resolved = path.resolve(SAFE_ROOT, decoded);

  if (!resolved.startsWith(SAFE_ROOT + path.sep))
    throw new Error('Access denied');

  if (!fs.statSync(resolved).isFile())
    throw new Error('Not a file');

  return fs.readFileSync(resolved, 'utf8');
}
```

### Whitelist Approach
```js
const ALLOWED = ['welcome.txt', 'readme.txt', 'docs.txt'];
if (!ALLOWED.includes(userInput)) throw new Error('File not permitted');
```

---

##  Key Points

- **Filters targeting one pattern miss variants** — `../` vs `..\/`
- **EISDIR = traversal is working** — you just hit a directory, adjust the path
- **ENOENT on encoded payload = server decodes once** — double encoding won't work
- **Only canonical path checking is reliable** — string filters are always bypassable

---

*All testing performed in an intentionally vulnerable lab environment for educational purposes.*
```
