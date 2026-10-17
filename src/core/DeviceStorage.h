/*
 *  Copyright (C) 2026 Frederic Ruget <fred@atlant.is>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KEEPASSXC_DEVICESTORAGE_H
#define KEEPASSXC_DEVICESTORAGE_H

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QLoggingCategory>
#include <QSet>
#include <QString>
#include <QStringList>

#include <functional>
#include <memory>

/**
 * Databases stored on a device instead of a file.
 *
 * A device database is named by a location, `yubikey:<serial>/<vault>.kdbx`
 * (`yubikey:/<vault>.kdbx` for the only YubiKey connected), used wherever
 * KeePassXC uses a file path as an identity.  Its bytes go between the
 * device and memory: no copy on disk.  The YubiKey is reached through
 * libyubiblob (https://github.com/douzebis/yb), which keeps the vault in the
 * YubiKey's PIV application and replaces it safely (an interrupted write
 * keeps the previous vault).  yb's store is either legacy (protected by
 * PIV: the PIV PIN) or post-quantum (protected by FIDO2: the FIDO2 PIN and
 * a touch per blob).
 *
 * Vaults are stored unencrypted by yb: a vault is already encrypted by its
 * master key, and a locked YubiKey must not lock the user out of it
 * (KeePassYB spec, yb spec 0046).  So a vault in a legacy store opens
 * without the PIN (its signature is checked); in a post-quantum store, it
 * needs the FIDO2 PIN and a touch, and when the YubiKey is locked, it can be
 * read with its checksum only, if the user agrees (yb spec 0044).
 *
 * Reads are served from a cache of the bytes, checked against the device
 * without the PIN; writes go to the device at once (write-through).
 */
/// KeePassYB's YubiKey log (yb spec 0047 S1), off by default:
/// QT_LOGGING_RULES="keepassyb.yubikey=true" (info level, as KeePassXC
/// builds without debug output).  Never logs a PIN, a
/// password or content.
Q_DECLARE_LOGGING_CATEGORY(lcYubiKey)

class DeviceStorage
{
public:
    /// Outcomes, as libyubiblob's status codes (yb spec 0039).
    enum Status
    {
        Ok = 0,
        NotFound = 1,
        StoreFull = 2,
        CardFull = 3,
        WrongPin = 4,
        PinBlocked = 5,
        NoDevice = 6,
        SeveralDevices = 7,
        NoStore = 8,
        CardRemoved = 9,
        Corrupted = 10,
        DefaultCredentials = 11,
        InvalidArgument = 12,
        Internal = 13,
        /// Post-quantum stores (yb spec 0028): a seal or the management key
        /// does not verify; nothing was returned or written.
        Tampered = 14,
        NoTouch = 15,
        /// 3 FIDO2 PIN attempts or fewer left: not tried.
        FewPinAttempts = 16,
        /// 3 wrong FIDO2 PINs in a row: unplug and replug the YubiKey.
        Replug = 17,
        /// The store's FIDO2 credential is gone (FIDO2 reset).
        NoCredential = 18,
        NoFido2Access = 19,
        /// A read without PIN of an encrypted blob (yb spec 0044).
        Encrypted = 20,
        /// KeePassXC built without libyubiblob.
        NotAvailable = -1,
    };

    /// yb's kind of store, which says which PIN protects it.
    enum class StoreKind
    {
        /// Protected by the YubiKey's PIV application: the PIV PIN.
        Legacy,
        /// Protected by its FIDO2 application: the FIDO2 PIN and a touch.
        PostQuantum,
    };

    /// A blob on the device, as listed without the PIN.
    struct BlobInfo
    {
        QString name;
        quint32 size = 0;
        quint32 mtime = 0;
        /// Changes with every write of the blob.
        quint32 generation = 0;
        bool encrypted = false;
    };

    /// The device side: libyubiblob, or a stand-in in tests.  `serial` is
    /// empty for the only YubiKey connected.  On failure, `error` says why
    /// (for people) and `pinTries`, after a wrong PIN, the tries left.
    class Backend
    {
    public:
        virtual ~Backend() = default;
        virtual Status list(const QString& serial, QList<BlobInfo>* blobs, QString* error) = 0;
        virtual Status storeKind(const QString& serial, StoreKind* kind, QString* error) = 0;
        virtual Status fetch(const QString& serial,
                             const QString& name,
                             const QByteArray& pin,
                             QByteArray* data,
                             QString* error,
                             int* pinTries) = 0;
        /// An unencrypted blob without any PIN or touch: legacy stores
        /// check its signature, post-quantum stores its checksum only.
        virtual Status
        fetchUnencrypted(const QString& serial, const QString& name, QByteArray* data, QString* error) = 0;
        virtual Status store(const QString& serial,
                             const QString& name,
                             const QByteArray& data,
                             bool encrypt,
                             const QByteArray& pin,
                             QString* error,
                             int* pinTries) = 0;
        virtual Status
        remove(const QString& serial, const QString& name, const QByteArray& pin, QString* error, int* pinTries) = 0;

        /// Called (on the calling thread) when the YubiKey waits for a touch.
        std::function<void()> touchNotice;
    };

    /// Asks the user for the PIN of the YubiKey `serial` (empty: the only
    /// one connected): the PIV PIN for a legacy store, the FIDO2 PIN for a
    /// post-quantum one.  A null string cancels.
    using PinPrompt = std::function<QString(const QString& serial, StoreKind kind)>;
    /// Asks whether to read the vault `blob` of a locked YubiKey (`reason`)
    /// without the YubiKey's own check, its checksum only (yb spec 0044).
    /// `kdbx3`: the vault is KDBX 3.1, whose own integrity check is weaker
    /// than KDBX 4's.  true: read it.
    using UnverifiedReadPrompt = std::function<bool(const QString& blob, const QString& reason, bool kdbx3)>;
    /// Something to tell the user, e.g. a vault now stored unencrypted.
    using Notice = std::function<void(const QString& message)>;
    /// The YubiKey waits for a touch.
    using TouchNotice = std::function<void()>;

    static DeviceStorage* instance();

    static bool isDeviceLocation(const QString& location);
    static QString location(const QString& serial, const QString& blob);
    /// Splits a location into the YubiKey's serial and the blob name.
    static bool parse(const QString& location, QString* serial, QString* blob);
    /// The vault name for a name the user typed: trimmed, with `.kdbx`
    /// appended if missing; empty if it cannot name a blob (empty, a `/`
    /// or a null character, more than 255 bytes in UTF-8).
    static QString vaultName(const QString& input);

    /// The vault's bytes: from the cache if the device still holds them,
    /// otherwise fetched (with the PIN).  With `mayAskPin` false (KeePassXC
    /// reading only the public headers, e.g. restoring tabs at start-up),
    /// nothing is fetched unless the PIN is already known.
    bool read(const QString& location, QByteArray* data, QString* error, bool mayAskPin = true);
    /// Store `data` on the device (with the PIN); updates the cache.
    bool write(const QString& location, const QByteArray& data, QString* error);

    /// The vaults (`*.kdbx` blobs) on a YubiKey; no PIN needed.  On
    /// failure, `error` is set, and `status` says why.
    QStringList listVaults(const QString& serial, QString* error, Status* status = nullptr);
    /// The vault's stored master password (`<vault>.passwd`), if one is
    /// there and usable: encrypted, in a post-quantum store (not on Windows
    /// yet).  Otherwise `password` is left empty, and nothing fails.
    bool readPassword(const QString& location, QString* password, QString* error);
    /// Whether the YubiKey holds a usable master password for the vault; no
    /// PIN needed.
    bool hasStoredPassword(const QString& location);
    /// Why the YubiKey's `<vault>.passwd` is not used (stored unencrypted,
    /// or in a legacy store); empty if there is none, or it is used.
    QString ignoredPasswordReason(const QString& location);
    /// Delete the vault's `<vault>.passwd` (with the PIN).
    bool removePassword(const QString& location, QString* error);
    /// Whether the vault's master password may be kept on its YubiKey:
    /// post-quantum stores only (not on Windows yet).
    bool canRememberPassword(const QString& location);
    /// Keep the vault's master password on its YubiKey, encrypted
    /// (`<vault>.passwd`), if `canRememberPassword`.
    bool storePassword(const QString& location, const QString& password, QString* error);

    void setPin(const QString& serial, const QString& pin);
    /// Forget the PIN of a YubiKey, overwriting it in memory.
    void forgetPin(const QString& serial);

    /// Replace the device side (tests); nullptr restores libyubiblob.
    void setBackend(std::unique_ptr<Backend> backend);
    void setPinPrompt(PinPrompt prompt);
    void setUnverifiedReadPrompt(UnverifiedReadPrompt prompt);
    void setNotice(Notice notice);
    void setTouchNotice(TouchNotice notice);
    /// Drop cached bytes (tests).
    void clearCache();

private:
    DeviceStorage();

    struct CacheEntry
    {
        QByteArray data;
        /// The vault's generation and size: detects a change on the
        /// device without the PIN.
        QByteArray fingerprint;
    };

    bool pinFor(const QString& serial, StoreKind kind, QByteArray* pin, QString* error);
    bool kindOf(const QString& serial, StoreKind* kind, QString* error);
    bool find(const QString& serial, const QString& blob, BlobInfo* info, Status* status, QString* error);
    bool
    fetch(const QString& serial, const QString& blob, StoreKind kind, QByteArray* data, QString* error, Status* status);
    bool
    readUnverified(const QString& serial, const QString& blob, const QString& reason, QByteArray* data, QString* error);
    bool passwordUsable(const QString& serial, const BlobInfo& passwd, QString* reason);
    QString describe(Status status, const QString& detail, const QString& blob, int pinTries, StoreKind kind) const;
    /// Run `f` on the GUI thread (prompts), blocking the calling thread.
    void onGuiThread(const std::function<void()>& f) const;

    friend class OpLog;
    /// The operation being timed, if any (operations do not overlap).
    class OpLog* m_op = nullptr;

    std::unique_ptr<Backend> m_backend;
    PinPrompt m_pinPrompt;
    UnverifiedReadPrompt m_unverifiedReadPrompt;
    Notice m_notice;
    TouchNotice m_touchNotice;
    /// Locations already told they are now stored unencrypted.
    QSet<QString> m_toldUnencrypted;
    QHash<QString, QByteArray> m_pins;
    QHash<QString, CacheEntry> m_cache;
};

#endif // KEEPASSXC_DEVICESTORAGE_H
