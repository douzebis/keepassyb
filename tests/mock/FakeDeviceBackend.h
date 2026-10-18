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

#ifndef KEEPASSXC_FAKEDEVICEBACKEND_H
#define KEEPASSXC_FAKEDEVICEBACKEND_H

// An in-memory YubiKey behind DeviceStorage, for the tests of vaults on a
// YubiKey (TestDeviceStorage, TestDeviceAutoSave).

#include <QCoreApplication>
#include <QSet>
#include <QTest>
#include <QThread>

#include "core/Database.h"
#include "core/DeviceStorage.h"
#include "core/Metadata.h"
#include "crypto/kdf/Kdf.h"
#include "format/KeePass2.h"
#include "keys/PasswordKey.h"

namespace fakedevice
{
    inline const QString Pin = QStringLiteral("654321");
    inline const QString Location = QStringLiteral("yubikey:/Passwords.kdbx");

    /// An in-memory YubiKey: blobs by name, each with a generation that
    /// changes with every store, and whether yb encrypted it.
    struct FakeDevice
    {
        QHash<QString, QByteArray> blobs;
        QHash<QString, quint32> generations;
        QSet<QString> encrypted;
        DeviceStorage::StoreKind kind = DeviceStorage::StoreKind::Legacy;
        /// A locked YubiKey: every operation with the PIN fails so.
        DeviceStorage::Status locked = DeviceStorage::Ok;
        quint32 nextGeneration = 1;
        int fetches = 0;
        int unverifiedFetches = 0;
        int stores = 0;
        /// Stores asked for, whether they succeed or not.
        int storeAttempts = 0;
        int touches = 0;
        int lists = 0;
        int kinds = 0;
        /// Whole reads of the card: refreshes (and a session's first use).
        int refreshes = 0;
        /// The snapshot (yb spec 0049): the card as last read, or as the
        /// session's own writes left it; empty until the first use.
        bool hasSnapshot = false;
        QHash<QString, QByteArray> snapBlobs;
        QHash<QString, quint32> snapGenerations;
        QSet<QString> snapEncrypted;
        /// Whether a backend call ran on the GUI (main) thread.
        bool calledOnMainThread = false;
        int pinTries = 3;
        bool full = false;
    };

    inline FakeDevice* fake = nullptr;

    /// Read the whole card into the snapshot.
    inline void takeSnapshot()
    {
        ++fake->refreshes;
        fake->snapBlobs = fake->blobs;
        fake->snapGenerations = fake->generations;
        fake->snapEncrypted = fake->encrypted;
        fake->hasSnapshot = true;
    }

    inline void ensureSnapshot()
    {
        if (!fake->hasSnapshot) {
            takeSnapshot();
        }
    }

    /// The YubiKey changed under KeePassYB (another program, or a test
    /// setting it up): its next question reads it again, as its next
    /// dialog would.
    inline void yubiKeyChanged()
    {
        fake->hasSnapshot = false;
    }

    /// A stand-in for libyubiblob, following its documented contract (yb
    /// specs 0039, 0028, 0044, 0049): a snapshot session, whose questions
    /// are answered from the store as last read, and whose writes read the
    /// card again (IF_UNCHANGED: Changed, writing nothing, if the blob
    /// changed since the snapshot); listing needs no PIN; a wrong PIN is
    /// WrongPin with the tries left; a missing blob is NotFound; a store
    /// without room is StoreFull and writes nothing; post-quantum stores
    /// ask for a touch per blob; reads without PIN refuse encrypted blobs.
    class FakeBackend : public DeviceStorage::Backend
    {
    public:
        DeviceStorage::Status refresh(const QString&, QString*) override
        {
            noteThread();
            takeSnapshot();
            return DeviceStorage::Ok;
        }

        DeviceStorage::Status list(const QString&, QList<DeviceStorage::BlobInfo>* blobs, QString*) override
        {
            ++fake->lists;
            noteThread();
            ensureSnapshot();
            blobs->clear();
            for (auto it = fake->snapBlobs.constBegin(); it != fake->snapBlobs.constEnd(); ++it) {
                blobs->append({it.key(),
                               static_cast<quint32>(it.value().size()),
                               0,
                               fake->snapGenerations.value(it.key()),
                               fake->snapEncrypted.contains(it.key())});
            }
            return DeviceStorage::Ok;
        }

        DeviceStorage::Status storeKind(const QString&, DeviceStorage::StoreKind* kind, QString*) override
        {
            ++fake->kinds;
            noteThread();
            ensureSnapshot();
            *kind = fake->kind;
            return DeviceStorage::Ok;
        }

        DeviceStorage::Status fetch(const QString&,
                                    const QString& name,
                                    const QByteArray& pin,
                                    QByteArray* data,
                                    QString* error,
                                    int* pinTries) override
        {
            if (auto status = withPin(pin, error, pinTries); status != DeviceStorage::Ok) {
                return status;
            }
            ensureSnapshot();
            if (!fake->snapBlobs.contains(name)) {
                *error = "no blob named " + name;
                return DeviceStorage::NotFound;
            }
            ++fake->fetches;
            *data = fake->snapBlobs.value(name);
            return DeviceStorage::Ok;
        }

        DeviceStorage::Status
        fetchUnencrypted(const QString&, const QString& name, QByteArray* data, QString* error) override
        {
            ensureSnapshot();
            if (!fake->snapBlobs.contains(name)) {
                *error = "no blob named " + name;
                return DeviceStorage::NotFound;
            }
            if (fake->snapEncrypted.contains(name)) {
                *error = name + " is encrypted";
                return DeviceStorage::Encrypted;
            }
            ++fake->unverifiedFetches;
            *data = fake->snapBlobs.value(name);
            return DeviceStorage::Ok;
        }

        DeviceStorage::Status store(const QString&,
                                    const QString& name,
                                    const QByteArray& data,
                                    bool encrypt,
                                    bool ifUnchanged,
                                    const QByteArray& pin,
                                    QString* error,
                                    int* pinTries) override
        {
            ++fake->storeAttempts;
            if (auto status = withPin(pin, error, pinTries); status != DeviceStorage::Ok) {
                return status;
            }
            ensureSnapshot();
            // The card read under the lock; the snapshot follows it.
            const bool changed = fake->blobs.contains(name) != fake->snapBlobs.contains(name)
                                 || fake->generations.value(name) != fake->snapGenerations.value(name);
            fake->snapBlobs = fake->blobs;
            fake->snapGenerations = fake->generations;
            fake->snapEncrypted = fake->encrypted;
            if (ifUnchanged && changed) {
                *error = name + " changed since the snapshot";
                return DeviceStorage::Changed;
            }
            if (fake->full) {
                *error = "not enough free objects";
                return DeviceStorage::StoreFull;
            }
            ++fake->stores;
            fake->blobs.insert(name, data);
            fake->generations.insert(name, fake->nextGeneration++);
            if (encrypt) {
                fake->encrypted.insert(name);
            } else {
                fake->encrypted.remove(name);
            }
            fake->snapBlobs = fake->blobs;
            fake->snapGenerations = fake->generations;
            fake->snapEncrypted = fake->encrypted;
            return DeviceStorage::Ok;
        }

        DeviceStorage::Status
        remove(const QString&, const QString& name, const QByteArray& pin, QString* error, int* pinTries) override
        {
            if (auto status = withPin(pin, error, pinTries); status != DeviceStorage::Ok) {
                return status;
            }
            fake->blobs.remove(name);
            fake->encrypted.remove(name);
            fake->snapBlobs = fake->blobs;
            fake->snapGenerations = fake->generations;
            fake->snapEncrypted = fake->encrypted;
            return DeviceStorage::Ok;
        }

    private:
        static void noteThread()
        {
            if (QThread::currentThread() == QCoreApplication::instance()->thread()) {
                fake->calledOnMainThread = true;
            }
        }

        DeviceStorage::Status withPin(const QByteArray& pin, QString* error, int* pinTries)
        {
            if (fake->locked != DeviceStorage::Ok) {
                *error = "locked";
                return fake->locked;
            }
            if (pin != Pin.toUtf8()) {
                *pinTries = --fake->pinTries;
                *error = "wrong PIN";
                return DeviceStorage::WrongPin;
            }
            fake->pinTries = 3;
            if (fake->kind == DeviceStorage::StoreKind::PostQuantum && touchNotice) {
                ++fake->touches;
                touchNotice();
                // Touched at once.
                if (touchedNotice) {
                    touchedNotice();
                }
            }
            return DeviceStorage::Ok;
        }
    };

    inline QSharedPointer<CompositeKey> key()
    {
        auto k = QSharedPointer<CompositeKey>::create();
        k->addKey(QSharedPointer<PasswordKey>::create("master"));
        return k;
    }

    /// A new database saved to the fake YubiKey, as KDBX 4 (Argon2, made
    /// fast for tests), the format of real vaults.
    inline void saveNewDatabase(const QString& name)
    {
        auto db = QSharedPointer<Database>::create();
        auto kdf = KeePass2::uuidToKdf(KeePass2::KDF_ARGON2D);
        kdf->setRounds(1);
        kdf->processParameters({{KeePass2::KDFPARAM_ARGON2_MEMORY, 1024}, {KeePass2::KDFPARAM_ARGON2_PARALLELISM, 1}});
        db->changeKdf(kdf);
        db->setKey(key());
        db->metadata()->setName(name);
        QString error;
        QVERIFY2(db->saveAs(Location, Database::Atomic, {}, &error), qPrintable(error));
    }
} // namespace fakedevice

#endif // KEEPASSXC_FAKEDEVICEBACKEND_H
