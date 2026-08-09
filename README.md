# wayward

Audit which applications hold persistent desktop-portal permissions on a Wayland
session — and find out who they actually belong to.

## The problem

Desktop portals grant permissions that outlive the application that asked for
them. The touchiest one is `ScreenCast`: once granted, the application receives a
*restore token* it can use to resume capturing your screen **without ever showing
you a dialog again**.

That permission is filed away in the `xdg-desktop-portal` permission store, and
that is where things break down. The portal identifies the requesting
application through an app ID derived from its sandbox. A native application —
anything installed via pacman or apt, or built from source — has no sandbox, so
its app ID is the empty string and the permission ends up filed under a random
token:

```console
$ gdbus call --session --dest org.freedesktop.impl.portal.PermissionStore \
    --object-path /org/freedesktop/impl/portal/PermissionStore \
    --method org.freedesktop.impl.portal.PermissionStore.Lookup \
    screencast 4fuEEh6prRn88cBf79d3jw

({'': ['yes']}, <('hyprland', uint32 3, <{'withCursor': <uint32 2>, ...}>)>)
   ^^
   the app ID is the empty string: nothing records which program this is
```

The result is a permanent screen-capture permission that cannot be traced back to
any application. Flatseal is no help, since it only manages Flatpak. Neither is
`flatpak permissions`, for the same reason. And the database directory lives
under `~/.local/share/flatpak/db` **even when Flatpak is not installed**, which
makes it easy to look in the wrong place entirely.

wayward exists to close that gap.

## Usage

```console
$ wayward               # terminal interface, with the bus monitor running inside
$ wayward list          # what is granted, with risk and age
$ wayward watch         # watch the bus and work out who each permission belongs to
$ wayward revoke TOKEN  # revoke a single permission
```

### The terminal interface

This is where the tool earns its keep, because it runs the bus monitor inside.
Open `wayward`, start sharing your screen in any application, and watch a token
that read "unattributed" acquire a name the moment the application asks for it.
That transition is precisely what the system gives you no way to see.

```
 wayward  1 permissions  2 activity                        ● listening
┌ permissions ────────────────────┐┌ details ──────────────────────────┐
│▌● ScreenCast 4fuEEh6prRn8…  ✦ obs││4fuEEh6prRn88cBf79d3jw             │
│ ● ScreenCast sWZGsB2YfzPC…  unat ││                                   │
│ ● Devices    camera         deni ││ScreenCast HIGH risk               │
```

Keys: `j`/`k` to move, `r` to revoke with a confirmation prompt, `R` to reload,
`tab` or `1`/`2` to switch views, `q` or Ctrl-C to quit. The `✦` marks anything
attributed during the current session.

`list` against a real machine:

```
  Devices  (devices)   HIGH risk · nothing granted
  access to input devices, camera and microphone
  ──────────────────────────────────────────────────────────────────
    • camera   denied

  ScreenCast  (screencast)   HIGH risk
  continuous screen capture, resumable without asking again
  ──────────────────────────────────────────────────────────────────
    • 4fuEEh6prRn88cBf79d3jw   unattributed
      granted     2026-08-08 18:46 (21 hours ago)
      output      DP-1
      cursor      embedded in the image
      backend     hyprland (format v3)

  Summary
    3 permissions across 2 tables · 2 granted, 2 high risk · 1 denied · 2 unattributed
```

Both commands take `--json` so they compose with other tooling. `revoke` takes
`--dry-run` to preview what would be deleted, `--table` to clear an entire table,
and `-y` to skip the confirmation.

## How attribution works

The permission store keeps the permission already anonymised, but the request
itself travels over D-Bus, and there the sender *is* identifiable. `wayward
watch` puts itself into monitor mode on the session bus and, whenever it sees a
call to a sensitive portal, resolves the connection to a PID via
`GetConnectionUnixProcessID` and from there to an executable in `/proc`.

Tying that identity to the granted token relies on how the portal builds the
`Request` object path:

```
/org/freedesktop/portal/desktop/request/1_72/wayward1
                                        ^^^^
                                        connection :1.72
```

That fragment is the requester's unique bus name with the leading colon stripped
and dots replaced by underscores. When the `Response` signal arrives carrying the
`restore_token`, undoing that transformation reveals who was behind it. The
resulting map is stored in `~/.local/state/wayward/attribution.json`.

## Limitations

Worth being clear about:

- **`watch` only sees what happens while it runs.** Permissions granted before
  its first run stay unattributed forever, because that information was never
  recorded anywhere. Cross-referencing `timeIssued` against the journal could
  narrow them down by approximation, but that is not implemented yet.
- **It needs monitor mode on the session bus**, which is yours, so no root is
  required. A connection in monitor mode can no longer issue calls, which is why
  wayward opens two.
- **Only `screencast` is decoded in detail.** Other tables are listed with their
  risk and raw data; the format of each is decided by whichever backend writes
  it.
- **A denial is not a risk.** The permission store also files rejections
  (`{'': ['no']}`), and wayward tells them apart from grants: they do not count
  toward the risk summary and do not need attribution. Treating them as exposures
  would be exactly the kind of false positive that teaches people to ignore the
  tool.
- **The table a token is attributed to is a heuristic**: the last portal
  interface that connection used. It is correct in the normal flow, where an
  application requests one permission at a time.
- Portals that **require** an app ID, such as `GlobalShortcuts`, reject native
  applications outright (`An app id is required`), so they never show up here.
  That is the correct behaviour, and in fact the one the rest of them need.

## Status

Verified against `xdg-desktop-portal` 1.22.1 and `xdg-desktop-portal-hyprland`
1.4.0 on Hyprland 0.56.0. Reading and revocation have been exercised end to end;
the grant path in `watch` is covered by tests of the correlation logic, but
completing it for real requires sharing a screen by hand.

Source comments are in Spanish; user-facing output is English.
