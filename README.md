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
$ wayward sessions      # who has a portal session open right now
$ wayward watch         # watch the bus and work out who each permission belongs to
$ wayward resolve       # recover the identity of permissions granted before you started watching
$ wayward revoke TOKEN  # revoke a single permission

$ wayward service install    # keep watching, from every graphical session
```

### Running it for real

Live attribution only works if something is listening at the instant an
application asks, which in practice means never. `wayward service install`
writes a systemd user unit that starts the monitor with your graphical session
and stops it with it — about 2 MB of memory, and no output beyond the grants it
records.

From then on every persistent grant is attributed as it happens and announced
with a desktop notification, so you find out that something acquired permanent
screen access at the moment it does, not three weeks later. High-risk grants
raise a critical notification that stays on screen until dismissed.

`wayward service status` shows whether it is running; `wayward service
uninstall` removes it and keeps the attribution map. Use `--no-notify` on
`watch` if you want the recording without the announcements.

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

## What is open right now

`list` answers who *could* capture your screen. `sessions` answers who has a
portal session open at this instant, which is usually the question that actually
worries someone.

```
$ wayward sessions

  Open portal sessions   1 session

    ● obs
      exe       /usr/bin/obs
      cmdline   obs
      pid       237842 · :1.72
      session   /org/freedesktop/portal/desktop/session/1_72/obs1
```

The portal publishes one object per live session at
`/org/freedesktop/portal/desktop/session/<sender>/<token>`, where `<sender>` is
the owning connection's unique bus name with the colon stripped and dots turned
into underscores. That transformation is invertible, so `1_72` becomes `:1.72`,
the bus turns it into a PID, and `/proc` turns that into an executable.

Unlike `watch`, this needs no monitor and no history: it is a point-in-time
query of live state, so it works on a machine where wayward was installed a
minute ago. It also catches sessions resumed from a restore token, which produce
no new grant for a monitor to see.

An open session is the thing capture runs on top of, not proof that capture is
happening this instant — but it does mean the application can resume without any
further prompt.

## Recovering the past

`watch` can only attribute what it witnesses, which is no help for a permission
granted months ago. `resolve` covers that: the permission store records a
`timeIssued`, and applications tend to log what they are doing at the moment
they do it, so correlating the two recovers what was never written down.

```
$ wayward resolve

  4fuEEh6prRn88cBf79d3jw   screencast · 2026-08-08 18:46 (1 day ago)
    obs              high     +0s   /usr/bin/obs
                     info: [pipewire] Screencast session created
    vesktop          medium   +0s   /usr/lib/vesktop/vesktop
                     [arRPC > process] detected game! OBS
```

The method is not tied to any particular application: journald attaches `_COMM`,
`_EXE` and `_PID` to every line, so it is enough to see who was writing around
the grant and rank them. A process that names the thing it just asked
permission for — "Screencast session created", in the same second — outranks one
that merely happened to be logging. Specific keywords beat generic ones, so a
line saying `screencast` wins over one that only mentions `pipewire`.

`--write` records the winners, and only `high` confidence by default. That
threshold matters: the second candidate above is a Discord client that really
can capture your screen and really was logging at that instant. It is a
plausible suspect and a wrong answer, which is precisely the kind of mistake a
security tool must not make silently.

## How live attribution works

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

- **`watch` only sees what happens while it runs**, which is why
  `service install` exists. For anything granted before that, use `resolve` —
  but its reach ends where journald's retention does, and it produces ranked
  candidates rather than certainties.
- **The unit hangs off `graphical-session.target`.** Sessions that do not
  activate it — some compositors started outside systemd — will need
  `default.target` instead, or the service never starts.
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
