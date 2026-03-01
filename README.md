# PPSM Monitor — Setup & Quick-Start

## What you need in the folder

Only **one file is required** to run the tool:

```
Invoke-PPSM.ps1       ← the entire application
```

The following files are **created automatically** by the tool and do not need to exist beforehand:

```
ppsm_ignored.txt      ← ignore list (created when you first ignore an app)
ppsm_config.yaml      ← default config file (created when you first use "Add to Config")
```

The following files are **optional** and can live anywhere on the machine — you browse to them at runtime:

```
your_config.yaml      ← any YAML config files you write manually
PPSM_Report_*.xlsx    ← Excel exports (saved wherever you choose)
```

The Python source files (`__init__.py`, `__main__.py`, `models.py`, and the `scanner/`, `ingestor/`, `engine/`, `renderer/`, `cli/` folders) are the **original Python version** of the app and are not used by `Invoke-PPSM.ps1`. You can delete them or keep them — they have no effect.

---

## One-time setup

Open **PowerShell as Administrator** and install the two required modules:

```powershell
Install-Module powershell-yaml -Scope CurrentUser
Install-Module ImportExcel     -Scope CurrentUser
```

You only need to do this once per machine.

---

## Running the app

Open a normal (non-admin) PowerShell window, navigate to the folder, and run:

```powershell
.\Invoke-PPSM.ps1
```

The GUI opens immediately. No parameters are needed.

> **If you see an error about running scripts being disabled**, run this once in an admin PowerShell:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

---

## Basic workflow

### 1. Scan the machine

Click **Start Scan**. The app immediately captures all active TCP and UDP connections and appends them to the grid. It then repeats automatically every N seconds (default 10 — change the number in the **Interval** box before clicking Start).

Click **Stop Scan** to halt. Rows already in the grid stay there.

### 2. Review what you see

Each row is a network connection. Key columns:

| Column | Meaning |
|---|---|
| **Application** | The executable that owns the connection |
| **Risk** | Colour-coded: Red = Critical, Orange = High, Yellow = Medium, Green = Low |
| **Authorized** | **Pending** (yellow) = not yet reviewed · **YES** (green) = approved · **NO** (red) = denied |

Rows start as **Pending** until you explicitly approve or deny them.

### 3. Approve or deny a connection

Right-click any row → **Add to Config...**

A dialog opens pre-filled with the connection details. Choose:
- **Authorized (YES)** — approve this connection
- **Denied (NO)** — flag it as not allowed

Set a **Risk** level and optionally add a **Note**, then click **Save Entry**.

The entry is written to a YAML file (default: `ppsm_config.yaml` in the same folder). You are then asked if you want to reload the file immediately — click **Yes** to see the row change from Pending to YES or NO in the grid.

### 4. Ignore noisy processes

For processes you never want to see (e.g. `svchost`, Windows Update agents):

Right-click any row → **Ignore Application**

The app will stop showing that process in the grid and exclude it from exports. To manage the list, click **Ignored Apps** in the toolbar.

### 5. Export a report

Click **Export Excel**, choose a filename, and the tool saves a formatted `.xlsx` report containing:

- **PPSM** — all deduplicated rows, colour-coded
- **Summary** — counts by risk level and authorization status
- **Undocumented Ports** — live connections with no config entry at all
- **Config Only** — config entries whose process was not seen in any scan

The machine name and timestamp are included in the header of every sheet.

---

## Loading existing YAML config files

If you already have YAML policy files, click **Load Config** and select them (you can select multiple at once). Their entries appear as **Config** source rows in the grid alongside live scan rows.

See [PPSM-Guide.md](PPSM-Guide.md) for the full YAML format reference.

---

## File reference

| File | Created by | Purpose |
|---|---|---|
| `Invoke-PPSM.ps1` | You | The entire application |
| `ppsm_ignored.txt` | App (auto) | Persisted ignore list, one app name per line |
| `ppsm_config.yaml` | App (auto) | Default file for entries saved via right-click → Add to Config |
| `*.yaml` / `*.yml` | You | Any additional YAML config files you write manually |
| `PPSM_Report_*.xlsx` | App (on export) | Excel reports — saved wherever you choose |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| *"Module not found"* on launch | Run the `Install-Module` commands in the One-time setup section above |
| *"running scripts is disabled"* | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` in an admin PowerShell |
| Export fails with *"sharing violation"* | The `.xlsx` file is open in Excel — close it and try again |
| Grid is empty after scanning | You may have all visible processes on the ignore list — check **Ignored Apps** |
