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

#include "DeviceStorage.h"

#include "config-keepassx.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QThread>

#ifdef KPXC_FEATURE_YUBIBLOB
#include <yubiblob.h>
#endif

Q_LOGGING_CATEGORY(lcYubiKey, "keepassyb.yubikey", QtWarningMsg)

/**
 * Times one operation on the YubiKey and logs it when it ends (yb spec 0047
 * S1): the total, split into waiting for the PIN prompt, waiting for a
 * touch (from the touch callback to the end), and the YubiKey itself.
 */
class OpLog
{
public:
    OpLog(DeviceStorage* storage, const char* what, const QString& blob)
        : m_storage(storage)
        , m_what(what)
        , m_blob(blob)
    {
        m_total.start();
        m_storage->m_op = this;
    }

    ~OpLog()
    {
        m_storage->m_op = nullptr;
        const auto total = m_total.elapsed();
        const auto touch = m_touch.isValid() ? m_touch.elapsed() : 0;
        qCInfo(lcYubiKey).noquote() << QString("%1 %2: %3 in %4 ms (PIN prompt %5 ms, touch %6 ms, YubiKey %7 ms)")
                                           .arg(m_what, m_blob, m_outcome)
                                           .arg(total)
                                           .arg(m_pinMs)
                                           .arg(touch)
                                           .arg(total - m_pinMs - touch);
    }

    void outcome(const QString& outcome)
    {
        m_outcome = outcome;
    }
    void addPinWait(qint64 ms)
    {
        m_pinMs += ms;
    }
    void touchStarted()
    {
        if (!m_touch.isValid()) {
            m_touch.start();
        }
    }

private:
    DeviceStorage* m_storage;
    QString m_what;
    QString m_blob;
    QString m_outcome = QStringLiteral("failed");
    QElapsedTimer m_total;
    QElapsedTimer m_touch;
    qint64 m_pinMs = 0;
};

namespace
{
    const QString kScheme = QStringLiteral("yubikey:");

    QString tr(const char* text)
    {
        return QCoreApplication::translate("DeviceStorage", text);
    }

    /// The vault's name without its `.kdbx` extension.
    QString stem(const QString& blob)
    {
        return blob.endsWith(".kdbx") ? blob.chopped(5) : blob;
    }

    /// The PIN that protects a store of this kind, as the user knows it.
    QString pinName(DeviceStorage::StoreKind kind)
    {
        return kind == DeviceStorage::StoreKind::PostQuantum ? tr("FIDO2 PIN") : tr("PIV PIN");
    }

    /// A KDBX file older than version 4: its content has no HMAC, so its own
    /// integrity check is weaker (KDBX 3.1: AES-CBC, header hash, stream
    /// start bytes).
    bool isBeforeKdbx4(const QByteArray& data)
    {
        // Two 4-byte signatures, then the version: minor (2 bytes), major
        // (2 bytes), little-endian.
        if (data.size() < 12) {
            return false;
        }
        const auto major = static_cast<quint8>(data[10]) | (static_cast<quint8>(data[11]) << 8);
        return major < 4;
    }

    /// The statuses of a post-quantum store whose FIDO2 side cannot be used
    /// now: a read without its check is then possible (yb spec 0044).
    bool isLocked(DeviceStorage::Status status)
    {
        switch (status) {
        case DeviceStorage::PinBlocked:
        case DeviceStorage::Replug:
        case DeviceStorage::FewPinAttempts:
        case DeviceStorage::NoCredential:
        case DeviceStorage::NoFido2Access:
            return true;
        default:
            return false;
        }
    }

#ifdef KPXC_FEATURE_YUBIBLOB
    static_assert(DeviceStorage::Ok == YUBIBLOB_OK && DeviceStorage::NotFound == YUBIBLOB_ERR_NOT_FOUND
                      && DeviceStorage::StoreFull == YUBIBLOB_ERR_STORE_FULL
                      && DeviceStorage::CardFull == YUBIBLOB_ERR_CARD_FULL
                      && DeviceStorage::WrongPin == YUBIBLOB_ERR_WRONG_PIN
                      && DeviceStorage::SeveralDevices == YUBIBLOB_ERR_SEVERAL_DEVICES
                      && DeviceStorage::Internal == YUBIBLOB_ERR_INTERNAL
                      && DeviceStorage::Tampered == YUBIBLOB_ERR_TAMPERED
                      && DeviceStorage::NoFido2Access == YUBIBLOB_ERR_NO_FIDO2_ACCESS
                      && DeviceStorage::Encrypted == YUBIBLOB_ERR_ENCRYPTED,
                  "DeviceStorage::Status mirrors libyubiblob's status codes");

    /// The device side on libyubiblob: one session per operation, so that a
    /// YubiKey unplugged and plugged back in between is simply found again.
    class YubiblobBackend : public DeviceStorage::Backend
    {
    public:
        YubiblobBackend()
        {
            // An incompatible library fails every call, saying so.
            m_compatible = yubiblob_abi_version() == YUBIBLOB_ABI_VERSION;
        }

        DeviceStorage::Status
        list(const QString& serial, QList<DeviceStorage::BlobInfo>* blobs, QString* error) override
        {
            Session s;
            auto status = open(serial, &s, error);
            if (status != DeviceStorage::Ok) {
                return status;
            }
            yubiblob_blob_info_t* found = nullptr;
            size_t count = 0;
            status = check(yubiblob_list(s.handle, &found, &count), error);
            if (status != DeviceStorage::Ok) {
                return status;
            }
            blobs->clear();
            for (size_t i = 0; i < count; ++i) {
                const auto& b = found[i];
                blobs->append({QString::fromUtf8(b.name), b.size, b.mtime, b.generation, b.encrypted});
            }
            yubiblob_blobs_free(found, count);
            return DeviceStorage::Ok;
        }

        DeviceStorage::Status storeKind(const QString& serial, DeviceStorage::StoreKind* kind, QString* error) override
        {
            Session s;
            auto status = open(serial, &s, error);
            if (status != DeviceStorage::Ok) {
                return status;
            }
            yubiblob_store_info_t info{};
            status = check(yubiblob_store_info(s.handle, &info), error);
            if (status == DeviceStorage::Ok) {
                *kind = info.kind == YUBIBLOB_KIND_POST_QUANTUM ? DeviceStorage::StoreKind::PostQuantum
                                                                : DeviceStorage::StoreKind::Legacy;
            }
            return status;
        }

        DeviceStorage::Status fetch(const QString& serial,
                                    const QString& name,
                                    const QByteArray& pin,
                                    QByteArray* data,
                                    QString* error,
                                    int* pinTries) override
        {
            Session s;
            auto status = open(serial, &s, error);
            if (status != DeviceStorage::Ok) {
                return status;
            }
            uint8_t* content = nullptr;
            size_t len = 0;
            const auto blob = name.toUtf8();
            status = check(yubiblob_fetch(s.handle,
                                          blob.constData(),
                                          reinterpret_cast<const uint8_t*>(pin.constData()),
                                          static_cast<size_t>(pin.size()),
                                          &content,
                                          &len),
                           error,
                           pinTries);
            if (status == DeviceStorage::Ok) {
                *data = QByteArray(reinterpret_cast<const char*>(content), static_cast<qsizetype>(len));
                yubiblob_buffer_free(content, len);
            }
            return status;
        }

        DeviceStorage::Status
        fetchUnencrypted(const QString& serial, const QString& name, QByteArray* data, QString* error) override
        {
            Session s;
            auto status = open(serial, &s, error);
            if (status != DeviceStorage::Ok) {
                return status;
            }
            uint8_t* content = nullptr;
            size_t len = 0;
            yubiblob_signature_t verdict{};
            const auto blob = name.toUtf8();
            status = check(yubiblob_fetch_unencrypted(s.handle, blob.constData(), &content, &len, &verdict), error);
            if (status == DeviceStorage::Ok) {
                *data = QByteArray(reinterpret_cast<const char*>(content), static_cast<qsizetype>(len));
                yubiblob_buffer_free(content, len);
            }
            return status;
        }

        DeviceStorage::Status store(const QString& serial,
                                    const QString& name,
                                    const QByteArray& data,
                                    bool encrypt,
                                    const QByteArray& pin,
                                    QString* error,
                                    int* pinTries) override
        {
            Session s;
            auto status = open(serial, &s, error);
            if (status != DeviceStorage::Ok) {
                return status;
            }
            const auto blob = name.toUtf8();
            return check(yubiblob_store(s.handle,
                                        blob.constData(),
                                        reinterpret_cast<const uint8_t*>(data.constData()),
                                        static_cast<size_t>(data.size()),
                                        encrypt ? YUBIBLOB_STORE_ENCRYPT : 0,
                                        reinterpret_cast<const uint8_t*>(pin.constData()),
                                        static_cast<size_t>(pin.size())),
                         error,
                         pinTries);
        }

        DeviceStorage::Status remove(const QString& serial,
                                     const QString& name,
                                     const QByteArray& pin,
                                     QString* error,
                                     int* pinTries) override
        {
            Session s;
            auto status = open(serial, &s, error);
            if (status != DeviceStorage::Ok) {
                return status;
            }
            const auto blob = name.toUtf8();
            return check(yubiblob_remove(s.handle,
                                         blob.constData(),
                                         reinterpret_cast<const uint8_t*>(pin.constData()),
                                         static_cast<size_t>(pin.size())),
                         error,
                         pinTries);
        }

    private:
        struct Session
        {
            yubiblob_session_t* handle = nullptr;
            ~Session()
            {
                yubiblob_close(handle);
            }
        };

        static void touched(void* user)
        {
            auto* self = static_cast<YubiblobBackend*>(user);
            if (self->touchNotice) {
                self->touchNotice();
            }
        }

        DeviceStorage::Status open(const QString& serial, Session* s, QString* error)
        {
            if (!m_compatible) {
                *error = tr("This libyubiblob (%1) is not the version KeePassYB was built with.")
                             .arg(QString::fromUtf8(yubiblob_version()));
                return DeviceStorage::NotAvailable;
            }
            auto status = check(yubiblob_open(serial.toUInt(), 0, &s->handle), error);
            if (status == DeviceStorage::Ok) {
                yubiblob_set_touch_callback(s->handle, &YubiblobBackend::touched, this);
            }
            return status;
        }

        static DeviceStorage::Status check(yubiblob_status_t status, QString* error, int* pinTries = nullptr)
        {
            if (status != YUBIBLOB_OK) {
                *error = QString::fromUtf8(yubiblob_last_error());
                if (pinTries) {
                    *pinTries = yubiblob_last_pin_tries();
                }
            }
            return static_cast<DeviceStorage::Status>(status);
        }

        bool m_compatible = false;
    };
#else
    /// Built without libyubiblob: every operation says so.
    class UnavailableBackend : public DeviceStorage::Backend
    {
    public:
        DeviceStorage::Status list(const QString&, QList<DeviceStorage::BlobInfo>*, QString* error) override
        {
            return unavailable(error);
        }
        DeviceStorage::Status storeKind(const QString&, DeviceStorage::StoreKind*, QString* error) override
        {
            return unavailable(error);
        }
        DeviceStorage::Status
        fetch(const QString&, const QString&, const QByteArray&, QByteArray*, QString* error, int*) override
        {
            return unavailable(error);
        }
        DeviceStorage::Status fetchUnencrypted(const QString&, const QString&, QByteArray*, QString* error) override
        {
            return unavailable(error);
        }
        DeviceStorage::Status
        store(const QString&, const QString&, const QByteArray&, bool, const QByteArray&, QString* error, int*) override
        {
            return unavailable(error);
        }
        DeviceStorage::Status remove(const QString&, const QString&, const QByteArray&, QString* error, int*) override
        {
            return unavailable(error);
        }

    private:
        static DeviceStorage::Status unavailable(QString* error)
        {
            *error = tr("This KeePassYB was built without YubiKey storage (libyubiblob).");
            return DeviceStorage::NotAvailable;
        }
    };
#endif

    std::unique_ptr<DeviceStorage::Backend> defaultBackend()
    {
#ifdef KPXC_FEATURE_YUBIBLOB
        return std::make_unique<YubiblobBackend>();
#else
        return std::make_unique<UnavailableBackend>();
#endif
    }
} // namespace

DeviceStorage::DeviceStorage()
{
    setBackend(nullptr);
}

DeviceStorage* DeviceStorage::instance()
{
    static DeviceStorage storage;
    return &storage;
}

bool DeviceStorage::isDeviceLocation(const QString& location)
{
    return location.startsWith(kScheme);
}

QString DeviceStorage::location(const QString& serial, const QString& blob)
{
    return kScheme + serial + "/" + blob;
}

bool DeviceStorage::parse(const QString& location, QString* serial, QString* blob)
{
    if (!isDeviceLocation(location)) {
        return false;
    }
    auto rest = location.mid(kScheme.size());
    auto slash = rest.indexOf('/');
    if (slash < 0 || slash == rest.size() - 1) {
        return false;
    }
    *serial = rest.left(slash);
    *blob = rest.mid(slash + 1);
    return true;
}

QString DeviceStorage::vaultName(const QString& input)
{
    auto name = input.trimmed();
    if (name.isEmpty() || name == ".kdbx" || name.contains('/') || name.contains(QChar(0))) {
        return {};
    }
    if (!name.endsWith(".kdbx")) {
        name += ".kdbx";
    }
    // yb's limit on blob names.
    return name.toUtf8().size() <= 255 ? name : QString();
}

QString
DeviceStorage::describe(Status status, const QString& detail, const QString& blob, int pinTries, StoreKind kind) const
{
    const auto pq = kind == StoreKind::PostQuantum;
    switch (status) {
    case NotFound:
        return tr("%1 is not on the YubiKey.").arg(blob);
    case StoreFull:
        return tr("Not enough room on the YubiKey to save %1: it needs room for a second copy while saving.").arg(blob);
    case CardFull:
        return tr("The YubiKey's memory ran out while saving %1: the previous version is kept. Make room on "
                  "the YubiKey, then save again.")
            .arg(blob);
    case WrongPin:
        if (pq) {
            return pinTries >= 0 ? tr("Wrong FIDO2 PIN (%1 tries left).").arg(pinTries) : tr("Wrong FIDO2 PIN.");
        }
        return pinTries >= 0 ? tr("Wrong PIN (%1 tries left).").arg(pinTries) : tr("Wrong PIN.");
    case PinBlocked:
        if (pq) {
            return tr("The YubiKey's FIDO2 PIN is blocked: only a FIDO2 reset clears it, and it destroys the "
                      "YubiKey's encrypted blobs.");
        }
        return tr("The YubiKey's PIN is blocked; unblock it with the PUK (e.g. ykman piv access unblock-pin).");
    case NoDevice:
        return tr("No YubiKey found.");
    case SeveralDevices:
        return tr("Several YubiKeys are connected: choose one by its serial number.");
    case NoStore:
        return tr("This YubiKey is not set up for yb (yb format).");
    case Corrupted:
        return tr("%1 on the YubiKey is corrupted or was tampered with: it was not read.").arg(blob);
    case Tampered:
        return tr("%1 failed the YubiKey's integrity check (its seal, or the management key: the YubiKey's PIV "
                  "application may have been reset): nothing was read or written.")
            .arg(blob);
    case NoTouch:
        return tr("The YubiKey was not touched in time.");
    case FewPinAttempts:
        return tr("Only 3 FIDO2 PIN attempts or fewer are left: KeePassYB does not try the PIN, as a blocked "
                  "FIDO2 PIN cannot be unblocked.");
    case Replug:
        return tr("Three wrong FIDO2 PINs in a row: unplug the YubiKey and plug it back in.");
    case NoCredential:
        return tr("The YubiKey's FIDO2 application was reset: the store's credential is gone.");
    case NoFido2Access:
        return tr("The YubiKey's FIDO2 side cannot be reached (FIDO application disabled, or no access to the "
                  "device).");
    default:
        return detail;
    }
}

void DeviceStorage::onGuiThread(const std::function<void()>& f) const
{
    // Saves run on a worker thread; prompts are GUI, so they run on the GUI
    // thread (which runs an event loop while it waits).
    auto* app = QCoreApplication::instance();
    if (app && QThread::currentThread() != app->thread()) {
        QMetaObject::invokeMethod(app, f, Qt::BlockingQueuedConnection);
    } else {
        f();
    }
}

bool DeviceStorage::pinFor(const QString& serial, StoreKind kind, QByteArray* pin, QString* error)
{
    if (!m_pins.contains(serial)) {
        QString entered;
        if (m_pinPrompt) {
            QElapsedTimer waited;
            waited.start();
            onGuiThread([&] { entered = m_pinPrompt(serial, kind); });
            if (m_op) {
                m_op->addPinWait(waited.elapsed());
            }
            qCInfo(lcYubiKey).noquote() << QString("%1 prompt: %2 after %3 ms")
                                               .arg(pinName(kind), entered.isNull() ? "cancelled" : "entered")
                                               .arg(waited.elapsed());
        }
        if (entered.isNull()) {
            *error = tr("The YubiKey's %1 is needed.").arg(pinName(kind));
            return false;
        }
        setPin(serial, entered);
    }
    *pin = m_pins.value(serial);
    return true;
}

bool DeviceStorage::kindOf(const QString& serial, StoreKind* kind, QString* error)
{
    QString detail;
    auto status = m_backend->storeKind(serial, kind, &detail);
    if (status != Ok) {
        *error = describe(status, detail, {}, -1, StoreKind::Legacy);
        return false;
    }
    return true;
}

bool DeviceStorage::find(const QString& serial, const QString& blob, BlobInfo* info, Status* status, QString* error)
{
    QList<BlobInfo> blobs;
    QString detail;
    QElapsedTimer listed;
    listed.start();
    *status = m_backend->list(serial, &blobs, &detail);
    qCInfo(lcYubiKey).noquote()
        << QString("list (for %1): status %2 in %3 ms").arg(blob).arg(*status).arg(listed.elapsed());
    if (*status != Ok) {
        *error = describe(*status, detail, blob, -1, StoreKind::Legacy);
        return false;
    }
    for (const auto& b : blobs) {
        if (b.name == blob) {
            *info = b;
            return true;
        }
    }
    *status = NotFound;
    *error = describe(NotFound, {}, blob, -1, StoreKind::Legacy);
    return false;
}

bool DeviceStorage::fetch(const QString& serial,
                          const QString& blob,
                          StoreKind kind,
                          QByteArray* data,
                          QString* error,
                          Status* status)
{
    QByteArray pin;
    if (!pinFor(serial, kind, &pin, error)) {
        *status = Internal;
        return false;
    }
    QString detail;
    int tries = -1;
    *status = m_backend->fetch(serial, blob, pin, data, &detail, &tries);
    pin.fill('\0');
    if (*status != Ok) {
        if (*status == WrongPin || *status == PinBlocked || *status == Replug || *status == FewPinAttempts) {
            forgetPin(serial);
        }
        *error = describe(*status, detail, blob, tries, kind);
        return false;
    }
    return true;
}

bool DeviceStorage::readUnverified(const QString& serial,
                                   const QString& blob,
                                   const QString& reason,
                                   QByteArray* data,
                                   QString* error)
{
    QByteArray bytes;
    QString detail;
    auto status = m_backend->fetchUnencrypted(serial, blob, &bytes, &detail);
    if (status != Ok) {
        *error = describe(status, detail, blob, -1, StoreKind::PostQuantum);
        return false;
    }
    bool agreed = false;
    if (m_unverifiedReadPrompt) {
        onGuiThread([&] { agreed = m_unverifiedReadPrompt(blob, reason, isBeforeKdbx4(bytes)); });
    }
    if (!agreed) {
        bytes.fill('\0');
        *error = reason;
        return false;
    }
    *data = bytes;
    return true;
}

bool DeviceStorage::read(const QString& location, QByteArray* data, QString* error, bool mayAskPin)
{
    QString serial, blob;
    if (!parse(location, &serial, &blob)) {
        *error = tr("Not a device location: %1").arg(location);
        return false;
    }
    OpLog op(this, "read", blob);
    BlobInfo info;
    Status status;
    if (!find(serial, blob, &info, &status, error)) {
        return false;
    }
    const auto current = QByteArray::number(info.generation) + ":" + QByteArray::number(info.size);
    auto cached = m_cache.constFind(location);
    if (cached != m_cache.constEnd() && cached->fingerprint == current) {
        *data = cached->data;
        op.outcome("cached, unchanged on the YubiKey");
        return true;
    }
    StoreKind kind;
    if (!kindOf(serial, &kind, error)) {
        return false;
    }

    // An unencrypted vault of a legacy store needs no PIN: its signature is
    // checked without it.
    if (!info.encrypted && kind == StoreKind::Legacy) {
        QString detail;
        status = m_backend->fetchUnencrypted(serial, blob, data, &detail);
        if (status != Ok) {
            *error = describe(status, detail, blob, -1, kind);
            return false;
        }
        m_cache.insert(location, {*data, current});
        op.outcome("read without PIN (legacy store, signature checked)");
        return true;
    }

    if (!mayAskPin && !m_pins.contains(serial)) {
        *error = tr("%1 is read from the YubiKey when unlocking.").arg(blob);
        return false;
    }
    if (!fetch(serial, blob, kind, data, error, &status)) {
        // A locked YubiKey: an unencrypted vault of a post-quantum store can
        // still be read, with its checksum only, if the user agrees.
        if (!(kind == StoreKind::PostQuantum && !info.encrypted && isLocked(status))) {
            return false;
        }
        const auto reason = *error;
        if (!readUnverified(serial, blob, reason, data, error)) {
            return false;
        }
        op.outcome("read with the checksum only (locked YubiKey, user agreed)");
    } else {
        op.outcome(kind == StoreKind::PostQuantum ? "read with the FIDO2 PIN" : "read with the PIN");
    }
    m_cache.insert(location, {*data, current});
    return true;
}

bool DeviceStorage::write(const QString& location, const QByteArray& data, QString* error)
{
    QString serial, blob;
    if (!parse(location, &serial, &blob)) {
        *error = tr("Not a device location: %1").arg(location);
        return false;
    }
    OpLog op(this, "write", blob);
    StoreKind kind;
    if (!kindOf(serial, &kind, error)) {
        return false;
    }
    // A vault stored encrypted by an older version is rewritten unencrypted.
    BlobInfo previous;
    Status status;
    QString ignored;
    const bool wasEncrypted = find(serial, blob, &previous, &status, &ignored) && previous.encrypted;

    QByteArray pin;
    if (!pinFor(serial, kind, &pin, error)) {
        return false;
    }
    QString detail;
    int tries = -1;
    // Unencrypted: the vault is encrypted by its master key, and a locked
    // YubiKey must not lock the user out of it.
    status = m_backend->store(serial, blob, data, false, pin, &detail, &tries);
    pin.fill('\0');
    if (status != Ok) {
        if (status == WrongPin || status == PinBlocked || status == Replug || status == FewPinAttempts) {
            forgetPin(serial);
        }
        *error = describe(status, detail, blob, tries, kind);
        return false;
    }
    BlobInfo info;
    const auto fingerprint = find(serial, blob, &info, &status, &ignored)
                                 ? QByteArray::number(info.generation) + ":" + QByteArray::number(info.size)
                                 : QByteArray();
    m_cache.insert(location, {data, fingerprint});
    op.outcome(QString("written, %1 bytes").arg(data.size()));
    if (wasEncrypted && !m_toldUnencrypted.contains(location) && m_notice) {
        m_toldUnencrypted.insert(location);
        const auto message =
            tr("%1 is now stored unencrypted on the YubiKey: it stays encrypted by its master password, and a "
               "locked YubiKey can no longer lock you out of it.")
                .arg(blob);
        onGuiThread([&] { m_notice(message); });
    }
    return true;
}

QStringList DeviceStorage::listVaults(const QString& serial, QString* error, Status* status)
{
    QList<BlobInfo> blobs;
    QString detail;
    auto result = m_backend->list(serial, &blobs, &detail);
    if (status) {
        *status = result;
    }
    if (result != Ok) {
        *error = describe(result, detail, {}, -1, StoreKind::Legacy);
        return {};
    }
    QStringList vaults;
    for (const auto& b : blobs) {
        if (b.name.endsWith(".kdbx")) {
            vaults << b.name;
        }
    }
    vaults.sort();
    return vaults;
}

bool DeviceStorage::passwordUsable(const QString& serial, const BlobInfo& passwd, QString* reason)
{
#ifdef Q_OS_WIN
    Q_UNUSED(serial)
    Q_UNUSED(passwd)
    *reason = tr("post-quantum stores are not supported on Windows yet");
    return false;
#else
    StoreKind kind;
    QString error;
    if (!kindOf(serial, &kind, &error)) {
        *reason = error;
        return false;
    }
    if (!passwd.encrypted) {
        *reason = tr("it is stored unencrypted: anyone holding the YubiKey can read it");
        return false;
    }
    if (kind != StoreKind::PostQuantum) {
        *reason = tr("it is in a legacy store, encrypted with classical cryptography");
        return false;
    }
    return true;
#endif
}

bool DeviceStorage::hasStoredPassword(const QString& location)
{
    QString serial, blob, error, reason;
    BlobInfo info;
    Status status;
    return parse(location, &serial, &blob) && find(serial, stem(blob) + ".passwd", &info, &status, &error)
           && passwordUsable(serial, info, &reason);
}

QString DeviceStorage::ignoredPasswordReason(const QString& location)
{
    QString serial, blob, error, reason;
    BlobInfo info;
    Status status;
    if (!parse(location, &serial, &blob) || !find(serial, stem(blob) + ".passwd", &info, &status, &error)
        || passwordUsable(serial, info, &reason)) {
        return {};
    }
    return tr("%1 on this YubiKey is not used: %2.").arg(stem(blob) + ".passwd", reason);
}

bool DeviceStorage::readPassword(const QString& location, QString* password, QString* error)
{
    QString serial, blob;
    if (!parse(location, &serial, &blob)) {
        *error = tr("Not a device location: %1").arg(location);
        return false;
    }
    password->clear();
    const auto passwd = stem(blob) + ".passwd";
    OpLog op(this, "read stored password", passwd);
    BlobInfo info;
    Status status;
    if (!find(serial, passwd, &info, &status, error)) {
        if (status == NotFound) {
            // No stored master password: nothing to read.
            error->clear();
            op.outcome("none");
            return true;
        }
        return false;
    }
    QString reason;
    if (!passwordUsable(serial, info, &reason)) {
        // Not safe to use: KeePassYB asks for the master password.
        op.outcome("not used: " + reason);
        return true;
    }
    QByteArray bytes;
    if (!fetch(serial, passwd, StoreKind::PostQuantum, &bytes, error, &status)) {
        return false;
    }
    // A password typed into `yb store` may end with a newline.
    if (bytes.endsWith('\n')) {
        bytes.chop(1);
    }
    *password = QString::fromUtf8(bytes);
    bytes.fill('\0');
    op.outcome("read with the FIDO2 PIN");
    return true;
}

bool DeviceStorage::removePassword(const QString& location, QString* error)
{
    QString serial, blob;
    StoreKind kind;
    if (!parse(location, &serial, &blob) || !kindOf(serial, &kind, error)) {
        return false;
    }
    QByteArray pin;
    if (!pinFor(serial, kind, &pin, error)) {
        return false;
    }
    const auto passwd = stem(blob) + ".passwd";
    OpLog op(this, "remove stored password", passwd);
    QString detail;
    int tries = -1;
    auto status = m_backend->remove(serial, passwd, pin, &detail, &tries);
    pin.fill('\0');
    if (status != Ok) {
        if (status == WrongPin || status == PinBlocked || status == Replug || status == FewPinAttempts) {
            forgetPin(serial);
        }
        *error = describe(status, detail, passwd, tries, kind);
        return false;
    }
    op.outcome("removed");
    return true;
}

bool DeviceStorage::canRememberPassword(const QString& location)
{
#ifdef Q_OS_WIN
    Q_UNUSED(location)
    return false;
#else
    QString serial, blob, error;
    StoreKind kind;
    return parse(location, &serial, &blob) && kindOf(serial, &kind, &error) && kind == StoreKind::PostQuantum;
#endif
}

bool DeviceStorage::storePassword(const QString& location, const QString& password, QString* error)
{
    QString serial, blob;
    if (!parse(location, &serial, &blob)) {
        *error = tr("Not a device location: %1").arg(location);
        return false;
    }
    if (!canRememberPassword(location)) {
        *error = tr("The master password is kept only on a YubiKey with a post-quantum store.");
        return false;
    }
    QByteArray pin;
    if (!pinFor(serial, StoreKind::PostQuantum, &pin, error)) {
        return false;
    }
    const auto passwd = stem(blob) + ".passwd";
    OpLog op(this, "store password", passwd);
    auto bytes = password.toUtf8();
    QString detail;
    int tries = -1;
    auto status = m_backend->store(serial, passwd, bytes, true, pin, &detail, &tries);
    pin.fill('\0');
    bytes.fill('\0');
    if (status != Ok) {
        if (status == WrongPin || status == PinBlocked || status == Replug || status == FewPinAttempts) {
            forgetPin(serial);
        }
        *error = describe(status, detail, passwd, tries, StoreKind::PostQuantum);
        return false;
    }
    op.outcome("stored, encrypted");
    return true;
}

void DeviceStorage::setPin(const QString& serial, const QString& pin)
{
    forgetPin(serial);
    m_pins.insert(serial, pin.toUtf8());
}

void DeviceStorage::forgetPin(const QString& serial)
{
    auto it = m_pins.find(serial);
    if (it != m_pins.end()) {
        it->fill('\0');
        m_pins.erase(it);
    }
}

void DeviceStorage::setBackend(std::unique_ptr<Backend> backend)
{
    m_backend = backend ? std::move(backend) : defaultBackend();
    m_backend->touchNotice = [this] {
        qCInfo(lcYubiKey) << "waiting for a touch";
        if (m_op) {
            m_op->touchStarted();
        }
        if (m_touchNotice) {
            m_touchNotice();
        }
    };
}

void DeviceStorage::setPinPrompt(PinPrompt prompt)
{
    m_pinPrompt = std::move(prompt);
}

void DeviceStorage::setUnverifiedReadPrompt(UnverifiedReadPrompt prompt)
{
    m_unverifiedReadPrompt = std::move(prompt);
}

void DeviceStorage::setNotice(Notice notice)
{
    m_notice = std::move(notice);
}

void DeviceStorage::setTouchNotice(TouchNotice notice)
{
    m_touchNotice = std::move(notice);
}

void DeviceStorage::clearCache()
{
    m_cache.clear();
    m_toldUnencrypted.clear();
}
