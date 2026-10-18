# <img src="share/icons/application/scalable/apps/keepassyb.svg" width="40" height="40"/> KeePassYB

**KeePassYB is an unofficial fork of [KeePassXC](https://keepassxc.org) that
can keep your password databases on a YubiKey**, through
[yb](https://github.com/douzebis/yb), instead of in a file.  It is not
affiliated with or endorsed by the KeePassXC Team.  Everything that is not
about the YubiKey is KeePassXC's work: see
[README-KeePassXC.md](README-KeePassXC.md) and
[keepassxc.org](https://keepassxc.org).

**Report problems with KeePassYB to
[its issues](https://github.com/douzebis/keepassyb/issues), never to
KeePassXC.**

## What it adds

- **Databases on the YubiKey.**  Open Database and Save As offer the
  YubiKey next to a file.  A database on the YubiKey is never written to
  the computer's disk.  Saving replaces it safely: an interrupted save keeps
  the previous version.
- **The database is stored unencrypted by yb**, as it is already encrypted
  by its master password.  So a locked YubiKey never locks you out of your
  passwords:
  - **Legacy stores** (yb's PIV store): the database opens without the
    YubiKey's PIN, which is needed only to save.
  - **Post-quantum stores** (yb's FIDO2 store): a KDBX 4 database opens
    without the FIDO2 PIN or a touch, which are needed only to save (KDBX 4
    checks its own integrity); a KDBX 3.1 one needs them to open too.  If
    the YubiKey is locked (blocked PIN, FIDO2 reset…), KeePassYB offers to
    open the database anyway, without the YubiKey's own integrity check;
    your master password still protects it.
- **The master password on the YubiKey** (`<database>.passwd`), so that
  the YubiKey and its FIDO2 PIN replace typing it.  This works only for a
  post-quantum store, stored encrypted.  The unlock dialog offers it.  A
  `.passwd` stored any other way is not used, and KeePassYB offers to
  delete it.

Every change to KeePassXC, and why: [KEEPASSYB.md](KEEPASSYB.md).

## Differences from KeePassXC

KeePassYB installs and runs next to KeePassXC without touching it: its own
name, icon, desktop and app IDs, and its own settings, cache and lock
files (`keepassyb` instead of `keepassxc`).  Some KeePassXC features are
switched off:

- **Browser integration:** the browser extension talks to KeePassXC.
- **Secret Service:** only one application can provide it.
- **Update checks:** they look for KeePassXC releases.

## Install

Releases are on the [releases page](https://github.com/douzebis/keepassyb/releases):

- a Linux AppImage;
- a Windows zip;
- a macOS disk image (Apple Silicon, unsigned).

On Windows, only yb's legacy stores are supported for now.  Set up the
YubiKey with yb first (`yb format`).

## Build

With [Nix](https://nixos.org), yb's build shell provides everything,
libyubiblob included:

```shell
git clone https://github.com/douzebis/keepassyb && cd keepassyb
curl -LO https://raw.githubusercontent.com/douzebis/yb/main/contrib/keepassxc/shell.nix
nix-shell
cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -C build
```

Without Nix, install KeePassXC's build dependencies
([INSTALL.md](INSTALL.md)), then libyubiblob 0.3 or later (`cargo cinstall
-p yubiblob` in yb's `rust/` directory).

## Branches and versions

- `keepassyb` (default): KeePassYB's releases, on top of a KeePassXC
  release (now 2.8.0-beta1).
- `feature/yubikey-storage`: the same feature on KeePassXC's `develop`,
  offered to KeePassXC (personal PR #1).

KeePassYB's versions are KeePassXC's, plus `-yb.<n>`: `2.8.0-beta1-yb.1`.

## License

GPL-2.0 or GPL-3.0, as KeePassXC ([COPYING](COPYING), [LICENSE.GPL-2](LICENSE.GPL-2),
[LICENSE.GPL-3](LICENSE.GPL-3)).  KeePassYB's icons are its own.
