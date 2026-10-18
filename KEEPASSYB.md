# What KeePassYB changes in KeePassXC

KeePassYB is KeePassXC 2.8.0-beta1 (branch `keepassyb`) with one addition:
password databases ("vaults") kept on a YubiKey, through
[yb](https://github.com/douzebis/yb)'s libyubiblob, instead of in a file.
Everything else is KeePassXC.  The design of each change is in yb's specs
(`docs/specs/` in the yb repository), cited below.

## Vaults on a YubiKey

- **One entry point:** `DeviceStorage` (`src/core/DeviceStorage.*`).  A
  vault is named by a location, `yubikey:<serial>/<vault>.kdbx`
  (`yubikey:/<vault>.kdbx` for the only YubiKey connected), used wherever
  KeePassXC uses a file path.  Its bytes go between the YubiKey and
  memory: no copy on disk.
- **The GUI:** Open and Save As offer the YubiKey's vaults next to a file
  ("A file…" first); a new database can be saved to the YubiKey.
  `keepassyb-cli` opens `yubikey:` locations too.
- **The build:** `KPXC_FEATURE_YUBIBLOB` (on), libyubiblob 0.5 or later
  through pkg-config.
- *Why:* yb keeps blobs in the YubiKey's PIV objects, and replaces them
  safely: an interrupted save keeps the previous version (yb invariant
  0001).  (Specs 0030, 0046.)

## What protects a vault

- **Stored unencrypted by yb:** a vault is already encrypted by its
  master key; encrypting it again with the YubiKey would let a locked
  YubiKey (blocked PIN, FIDO2 reset) lock the user out of it.  A vault an
  older version stored encrypted is rewritten unencrypted, and the user
  told.
- **The PIN only to write:** a legacy store's vault opens without the PIN
  (its signature is checked); in a post-quantum store, a KDBX 4 vault
  opens without the PIN or a touch, as KDBX 4 checks its own integrity
  (an HMAC per block, keyed by the master key).  A KDBX 3.1 vault, whose
  own check is weaker, gets the YubiKey's full check.
- **A locked YubiKey:** a post-quantum vault can still be read with its
  checksum only, after the user agrees; saving then needs a file.
- **The stored master password** (`<vault>.passwd`, "Remember the master
  password on this YubiKey") is used only if encrypted, in a post-quantum
  store.
- **The PIN** is asked at the first operation that needs it, kept until
  the vault is locked.
- (Specs 0044, 0046, 0047 S4.)

## A slow device

- **One read to open:** a libyubiblob snapshot session per YubiKey
  answers the listing, the store's kind and reads without the PIN.  It is
  read again when the "Open from YubiKey" dialog, the unlock dialog and
  Save As open.  Unlocking reads nothing.  *Why:* each read of the store
  costs time on the YubiKey.  (Spec 0050 S1.)
- **Off the GUI thread:** YubiKey operations run on a worker thread, one
  at a time; the window keeps responding.  (Spec 0047 S2.)
- **A progress dialog** for slow operations ("Saving … to the
  YubiKey…"), hidden while a prompt is shown.  When the YubiKey waits for
  a touch, it says what for ("Touch your YubiKey to save
  Passwords.kdbx."), at once; once the touch is over, it says again what
  the operation does.
  (Specs 0047 S4, 0051 S5.)
- **No automatic challenge-response scan** in a vault's unlock dialog:
  it would reach the same YubiKey; the refresh button still scans.
  (Spec 0047 S5.)
- **A log:** `QT_LOGGING_RULES="keepassyb.yubikey=true"` shows each
  YubiKey operation, its duration, its PIN and touch waits, and why a
  vault was marked modified.  No PIN, password or content is logged.
  (Spec 0047 S1.)

## Saving

- **Automatically, about 0.25 s after the last request:** a change, the
  end of a YubiKey operation, or Save; a burst makes one write.  Lock,
  close and exit save at once.  KeePassXC's two auto-save settings apply.
  *Why:* the PIN prompt and the touch then follow the edit that needs
  them.  (Specs 0050 S2, 0051 S1.)
- **Only real changes:** before a write, the vault's content is compared
  with what was read or saved, leaving out what changes without a data
  change (KeePassXC's random padding, the view state, access times and
  counts, modification times).  Unchanged: nothing is written.  *Why:*
  a change of view (an expanded group) marks a database modified.
  (Spec 0047 S2.)
- **A failed save:** an automatic one shows the reason with Retry, and is
  not tried again until the content changes (no loop of prompts); at
  lock or exit: Retry, Save as a file, Discard (confirmed), Cancel.
  (Specs 0047 S3, 0050 S3.)
- **Never overwrite another program's change:** the vault on the YubiKey
  must still be the version the open vault is based on, and must not
  have changed since the snapshot (libyubiblob's `IF_UNCHANGED`, under
  yb's card lock).  Otherwise nothing is written, and KeePassXC's own
  question for a file changed on disk follows: merge then save,
  overwrite, discard, cancel.  (Specs 0048, 0049, 0050 S3.)

## Room on the YubiKey

- **No random padding without KeeShare:** KeePassXC adds 64 to 512 random
  bytes to every save, against a size side channel through KeeShare
  (KeePassXC commit `72fc0069`).  It is kept for a vault with a KeeShare
  group, and left out otherwise: about 10% of a small vault.
- **No history by default:** a vault first saved to a YubiKey keeps no
  old versions of its entries; the user is told, and may raise the
  setting (Database settings, History).
- (Spec 0051.)

## Its own identity

- **Next to KeePassXC, not in its place** (etiquette towards the
  KeePassXC Team): application ID `io.github.douzebis.KeePassYB`,
  program `keepassyb` and `keepassyb-cli`, its own configuration, data
  and lock files, icons, desktop entry (with the program's full path),
  AppStream file, polkit action and macOS bundle.  "KeePassYB is not
  affiliated with or endorsed by the KeePassXC Team."  KeePassXC's
  donation links are hidden.
- **Features off by default:** browser integration, the Secret Service,
  update checks (they would contact or impersonate KeePassXC's
  services).
- **Versions:** from tags `v<KeePassXC version>-yb.<n>`.
- (Spec 0046.)

## Build, CI, tests

- **CI** (`.github/workflows/keepassyb.yaml`): Linux (yb's Nix build
  shell, tests under a virtual X server), macOS (Homebrew), Windows (Qt
  and vcpkg; legacy stores only), with libyubiblob built from yb at
  `YB_REV`.  KeePassXC's own workflows run only upstream.
- **CMake** looks for libyubiblob again at each configure, so a build
  directory follows a new libyubiblob.
- **Tests:** `TestDeviceStorage` and `TestDeviceAutoSave`, on an
  in-memory YubiKey that follows libyubiblob's contract
  (`tests/mock/FakeDeviceBackend.h`, a snapshot session); `TestKeePassYB`
  for the identity.
