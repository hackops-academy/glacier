# Glacier packaging (Kali / Debian-based desktop install)

Turns Glacier into a normal desktop application, launched the same way
you'd launch Burp Suite or OWASP ZAP: an icon in the Applications menu
(and a `glacier` command), one click, no terminal juggling.

## Install

```bash
cd glacier-main
./packaging/install.sh
```

This is a **per-user** install - no `sudo` is needed for Glacier itself
(only to `apt install` a couple of system packages, if any are missing,
and only with your confirmation). It:

- copies the app into `~/.local/share/glacier`
- creates the Python venv and installs Python deps there
- runs `npm install` for the Electron HUD
- installs the app icon into `~/.local/share/icons/hicolor/*/apps/`
- installs the `glacier` command into `~/.local/bin/glacier`
- adds a "Glacier" entry to your desktop's Applications menu

Takes a few minutes the first time (Electron download). Re-running the
installer is safe - it just refreshes everything in place.

## Launch

- From the Applications menu: search **Glacier**, click it.
- From a terminal: `glacier`

Either way, the launcher starts the proxy (`:8081`) and API (`:8090`)
in the background, waits for them to come up, then opens the HUD.
Closing the HUD window stops the background processes automatically.
Logs land in `~/.local/share/glacier-run/logs/` if something needs
debugging.

## Uninstall

```bash
./packaging/uninstall.sh
```

Removes the app, the menu entry, the icon, the `glacier` command, and
(after confirming) all captured traffic/findings.

## Notes

- The database (`proxy/glacier.db`) lives inside the per-user install
  directory, so there's no root-owned files getting in the way of the
  app writing to it - the whole thing behaves like a normal user app.
- If `~/.local/bin` isn't already on your `PATH`, the installer tells
  you what to add to your shell rc file. The Applications menu entry
  works either way.
