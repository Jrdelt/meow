# Open Security & Triage Issues (`meow`)

Active backlog of security hardening and CVE-grounding issues. Work **one issue at a time** per `AGENTS.md`.
- Log newly discovered bugs or security findings here with the next `ISS-NNN` ID.
- Once an issue is fixed and passes `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`, move its entry to `issue/fixed issues.md`.

---

`ISS-001` through `ISS-031` are resolved and verified in `issue/fixed issues.md`. Both open issues are Windows-only and cannot be run or verified where meow is developed (no Windows machine, no PowerShell); neither affects macOS or Linux.

### `ISS-032` [Low / Security] — Windows: A Workspace Folder That Already Exists Keeps Its Owner and Other Accounts' Access Entries
- **Location:** `src/workspace.rs` (`restrict_dir`, `restrict_file`, `enforce_private_tree`, Windows versions)
- **Problem:** Found by the 2026-11 security audit by reading the code; never run. On Windows a workspace folder is made private with `icacls <path> /inheritance:r /grant:r <user>:(OI)(CI)F`. That removes inherited entries and sets this user's own, but leaves explicit entries for other accounts, and the folder's owner, as they were; files inside that carry their own entries are not touched. Another account on the same machine that creates `.meow` in a shared project folder beforehand, with an entry for itself, can still read the workspace after the user opens it with `--local`: `runtime.json` (the session token), `graph.json`, the chats. On macOS and Linux the same folder is refused (it cannot be made private by someone who does not own it), and since `ISS-024` a `./.meow` the user did not make is opened only after a yes.
- **Proposed Fix:** Before using an existing workspace folder, require that the current user owns it. Replace the whole access list with a protected one that holds a single inheritable entry for the current user, applied to the tree, instead of adding to what is there (`icacls /reset` on the children, or `SetNamedSecurityInfoW` with `PROTECTED_DACL_SECURITY_INFORMATION`).
- **Needs:** A Windows machine or a Windows CI job that creates a folder with an explicit `Everyone` entry, opens it as a workspace, and reads `icacls` output back.

### `ISS-033` [Low / Availability] — `install.ps1`: The Location Database Download Has No Size Limit and Has Never Been Run
- **Location:** `install.ps1` (`Get-GeoFile`)
- **Problem:** `install.sh` stops the location database at 200 MB packed and 512 MB unpacked (`ISS-027`). The PowerShell installer downloads and unpacks the same files without a limit, and reads the unpacked file into memory to check it. A wrong or hostile answer from the download host could fill the disk or memory. Like the rest of `install.ps1`, this function has never been run.
- **Proposed Fix:** Check the packed size after the download, copy the unpacked stream in blocks up to the limit, and check the file's tail without reading all of it.
- **Needs:** A run on Windows PowerShell 5.1 and PowerShell 7.
