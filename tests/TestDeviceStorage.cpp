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

#include "TestDeviceStorage.h"

#include <QCoreApplication>
#include <QSet>
#include <QSignalSpy>
#include <QTest>
#include <QThread>

#include "core/CustomData.h"
#include "core/Database.h"
#include "core/DeviceStorage.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "crypto/Crypto.h"
#include "crypto/kdf/Kdf.h"
#include "format/KeePass2.h"
#include "keys/PasswordKey.h"

#include "mock/FakeDeviceBackend.h"

QTEST_GUILESS_MAIN(TestDeviceStorage)

using namespace fakedevice;

void TestDeviceStorage::initTestCase()
{
    QVERIFY(Crypto::init());
}

void TestDeviceStorage::init()
{
    delete fake;
    fake = new FakeDevice;
    auto* storage = DeviceStorage::instance();
    storage->setBackend(std::make_unique<FakeBackend>());
    storage->setPinPrompt([](const QString&, DeviceStorage::StoreKind) { return Pin; });
    storage->setUnverifiedReadPrompt({});
    storage->setNotice({});
    storage->setTouchNotice({});
    storage->clearCache();
    storage->setQuitting(false);
    storage->forgetPin("");
}

void TestDeviceStorage::cleanupTestCase()
{
    DeviceStorage::instance()->setBackend(nullptr);
    DeviceStorage::instance()->setPinPrompt({});
    DeviceStorage::instance()->setUnverifiedReadPrompt({});
    DeviceStorage::instance()->setNotice({});
    DeviceStorage::instance()->setTouchNotice({});
    delete fake;
    fake = nullptr;
}

void TestDeviceStorage::testLocations()
{
    QVERIFY(DeviceStorage::isDeviceLocation("yubikey:12345678/Passwords.kdbx"));
    QVERIFY(!DeviceStorage::isDeviceLocation("/home/me/Passwords.kdbx"));
    QString serial, blob;
    QVERIFY(DeviceStorage::parse("yubikey:12345678/Passwords.kdbx", &serial, &blob));
    QCOMPARE(serial, QString("12345678"));
    QCOMPARE(blob, QString("Passwords.kdbx"));
    QVERIFY(DeviceStorage::parse("yubikey:/Work.kdbx", &serial, &blob));
    QVERIFY(serial.isEmpty());
    QVERIFY(!DeviceStorage::parse("yubikey:12345678/", &serial, &blob));

    // A device location is its own canonical path (there is no file).
    Database db(Location);
    QCOMPARE(db.canonicalFilePath(), Location);
}

/// The name typed when saving a database on the YubiKey.
void TestDeviceStorage::testVaultName()
{
    QCOMPARE(DeviceStorage::vaultName("Travel"), QString("Travel.kdbx"));
    QCOMPARE(DeviceStorage::vaultName("  Travel.kdbx "), QString("Travel.kdbx"));
    QCOMPARE(DeviceStorage::vaultName("Mes mots de passe"), QString("Mes mots de passe.kdbx"));
    QVERIFY(DeviceStorage::vaultName("").isEmpty());
    QVERIFY(DeviceStorage::vaultName("  ").isEmpty());
    QVERIFY(DeviceStorage::vaultName(".kdbx").isEmpty());
    QVERIFY(DeviceStorage::vaultName("a/b").isEmpty());
    QVERIFY(DeviceStorage::vaultName(QString("a") + QChar(0) + "b").isEmpty());
    // yb's limit: 255 bytes in UTF-8, ".kdbx" included.
    QCOMPARE(DeviceStorage::vaultName(QString(250, 'x')).size(), 255);
    QVERIFY(DeviceStorage::vaultName(QString(251, 'x')).isEmpty());
    // "é" is 2 bytes: 125 of them + ".kdbx" is 255 bytes, 126 is 257.
    QCOMPARE(DeviceStorage::vaultName(QString(125, QChar(0xe9))).size(), 130);
    QVERIFY(DeviceStorage::vaultName(QString(126, QChar(0xe9))).isEmpty());
}

/// A database saved to the device and opened from it.  It is stored
/// unencrypted by yb (its master key encrypts it), so a vault of a legacy
/// store opens without the PIN.
void TestDeviceStorage::testSaveAndOpen()
{
    saveNewDatabase("on the YubiKey");
    QCOMPARE(fake->stores, 1);
    QVERIFY(fake->blobs.value("Passwords.kdbx").size() > 0);
    QVERIFY(!fake->encrypted.contains("Passwords.kdbx"));

    DeviceStorage::instance()->clearCache();
    DeviceStorage::instance()->forgetPin("");
    int prompts = 0;
    DeviceStorage::instance()->setPinPrompt([&prompts](const QString&, DeviceStorage::StoreKind) {
        ++prompts;
        return Pin;
    });
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(db->metadata()->name(), QString("on the YubiKey"));
    QCOMPARE(db->filePath(), Location);
    QCOMPARE(fake->unverifiedFetches, 1);
    QCOMPARE(prompts, 0);
    QVERIFY(!db->isModified());
}

/// Opening again (unlock after lock, header reads) uses the cache: the
/// device is only asked whether the vault changed, without the PIN.
void TestDeviceStorage::testOpenUsesTheCache()
{
    saveNewDatabase("cached");
    for (int i = 0; i < 3; ++i) {
        auto db = QSharedPointer<Database>::create();
        QString error;
        QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    }
    QCOMPARE(fake->fetches + fake->unverifiedFetches, 0);
}

/// A vault changed on the device (another computer) is fetched again.
void TestDeviceStorage::testChangedVaultIsFetchedAgain()
{
    saveNewDatabase("first");
    auto stored = fake->blobs.value("Passwords.kdbx");
    saveNewDatabase("second");
    // Elsewhere, the first version is stored back.
    fake->blobs.insert("Passwords.kdbx", stored);
    fake->generations.insert("Passwords.kdbx", fake->nextGeneration++);
    yubiKeyChanged();

    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(db->metadata()->name(), QString("first"));
    QCOMPARE(fake->unverifiedFetches, 1);
}

/// A save the device refuses (store full) fails with a clear message, and
/// leaves the database modified, so nothing is lost.
void TestDeviceStorage::testStoreFullKeepsTheDatabaseModified()
{
    saveNewDatabase("before");
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY(db->open(Location, key(), &error));
    db->metadata()->setName("after");
    fake->full = true;
    QVERIFY(!db->save(Database::Atomic, {}, &error));
    QVERIFY(error.contains("Not enough room"));
    QVERIFY(db->isModified());

    fake->full = false;
    QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
    QVERIFY(!db->isModified());
}

/// The PIN is asked when first needed, then held; forgetting it (at lock)
/// makes the next save ask again.
void TestDeviceStorage::testPinIsAskedOnceAndForgotten()
{
    int prompts = 0;
    DeviceStorage::instance()->setPinPrompt([&prompts](const QString&, DeviceStorage::StoreKind) {
        ++prompts;
        return Pin;
    });
    saveNewDatabase("one");
    saveNewDatabase("two");
    QCOMPARE(prompts, 1);
    DeviceStorage::instance()->forgetPin("");
    saveNewDatabase("three");
    QCOMPARE(prompts, 2);

    // A cancelled prompt fails the save, and nothing is stored.
    DeviceStorage::instance()->forgetPin("");
    DeviceStorage::instance()->setPinPrompt([](const QString&, DeviceStorage::StoreKind) { return QString(); });
    auto db = QSharedPointer<Database>::create();
    db->setKey(key());
    QString error;
    QVERIFY(!db->saveAs(Location, Database::Atomic, {}, &error));
    QCOMPARE(fake->stores, 3);
}

/// Reading only the public headers (no key: KeePassXC restoring tabs at
/// start-up) never asks for the PIN: a legacy store's vault is read
/// without it, a post-quantum store's is not read; unlocking asks once.
void TestDeviceStorage::testHeaderReadDoesNotAskForThePin()
{
    saveNewDatabase("restored");
    DeviceStorage::instance()->clearCache();
    DeviceStorage::instance()->forgetPin("");
    int prompts = 0;
    DeviceStorage::instance()->setPinPrompt([&prompts](const QString&, DeviceStorage::StoreKind) {
        ++prompts;
        return Pin;
    });

    // Legacy: read without the PIN (the vault is unencrypted).
    QString error;
    QSharedPointer<Database>::create()->open(Location, nullptr, &error);
    QCOMPARE(prompts, 0);
    QCOMPARE(fake->fetches, 0);

    // Post-quantum, KDBX 4: read with the checksum only, no PIN either.
    fake->kind = DeviceStorage::StoreKind::PostQuantum;
    DeviceStorage::instance()->clearCache(); // a reformat, for the caches
    QSharedPointer<Database>::create()->open(Location, nullptr, &error);
    QCOMPARE(prompts, 0);
    QCOMPARE(fake->fetches, 0);

    auto db = QSharedPointer<Database>::create();
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(prompts, 0);
}

/// A vault that is not on the YubiKey: opening fails, saying so.
void TestDeviceStorage::testMissingVault()
{
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY(!db->open(Location, key(), &error));
    QVERIFY2(error.contains("is not on the YubiKey"), qPrintable(error));
}

/// A wrong PIN fails with the tries left, and is forgotten: the next
/// operation asks again.  (A post-quantum store and a vault stored
/// encrypted by an older version: reading it needs the PIN.)
void TestDeviceStorage::testWrongPin()
{
    saveNewDatabase("pin");
    fake->encrypted.insert("Passwords.kdbx");
    yubiKeyChanged();
    fake->kind = DeviceStorage::StoreKind::PostQuantum;
    DeviceStorage::instance()->clearCache(); // a reformat, for the caches
    DeviceStorage::instance()->clearCache();
    DeviceStorage::instance()->forgetPin("");
    QStringList answers{"000000", Pin};
    int prompts = 0;
    DeviceStorage::instance()->setPinPrompt(
        [&](const QString&, DeviceStorage::StoreKind) { return answers.value(prompts++); });

    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY(!db->open(Location, key(), &error));
    QVERIFY2(error.contains("Wrong FIDO2 PIN (2 tries left)"), qPrintable(error));
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(prompts, 2);
}

/// The vault list holds the `*.kdbx` blobs only, sorted.
void TestDeviceStorage::testListVaults()
{
    fake->blobs.insert("b.kdbx", "x");
    fake->blobs.insert("a.kdbx", "x");
    fake->blobs.insert("a.passwd", "x");
    QString error;
    QCOMPARE(DeviceStorage::instance()->listVaults({}, &error), QStringList({"a.kdbx", "b.kdbx"}));
}

/// The vault's master password, kept on the YubiKey as `<vault>.passwd`,
/// is read without its final newline, only when it is encrypted in a
/// post-quantum store; without a usable one, nothing is read and nothing
/// fails (KeePassYB then asks for the master password).
void TestDeviceStorage::testStoredMasterPassword()
{
    auto* storage = DeviceStorage::instance();
    QString password, error;
    QVERIFY(storage->readPassword(Location, &password, &error));
    QVERIFY(password.isEmpty());
    QVERIFY(!storage->hasStoredPassword(Location));
    QVERIFY(storage->ignoredPasswordReason(Location).isEmpty());

    // Encrypted, in a post-quantum store: used.
    fake->kind = DeviceStorage::StoreKind::PostQuantum;
    DeviceStorage::instance()->clearCache(); // a reformat, for the caches
    fake->blobs.insert("Passwords.passwd", "correct horse\n");
    fake->encrypted.insert("Passwords.passwd");
    yubiKeyChanged();
#ifndef Q_OS_WIN
    QVERIFY(storage->hasStoredPassword(Location));
    QVERIFY(storage->readPassword(Location, &password, &error));
    QCOMPARE(password, QString("correct horse"));
    QVERIFY(storage->ignoredPasswordReason(Location).isEmpty());
#endif

    // Unencrypted: anyone holding the YubiKey could read it.
    fake->encrypted.remove("Passwords.passwd");
    yubiKeyChanged();
    QVERIFY(!storage->hasStoredPassword(Location));
    QVERIFY(storage->readPassword(Location, &password, &error));
    QVERIFY(password.isEmpty());
    QVERIFY2(storage->ignoredPasswordReason(Location).contains("not used"), "unencrypted");

    // In a legacy store: classical encryption.
    fake->kind = DeviceStorage::StoreKind::Legacy;
    DeviceStorage::instance()->clearCache(); // a reformat, for the caches
    fake->encrypted.insert("Passwords.passwd");
    yubiKeyChanged();
    QVERIFY(!storage->hasStoredPassword(Location));
    QVERIFY(storage->readPassword(Location, &password, &error));
    QVERIFY(password.isEmpty());
    QVERIFY(!storage->ignoredPasswordReason(Location).isEmpty());

    // The user may delete it.
    QVERIFY2(storage->removePassword(Location, &error), qPrintable(error));
    QVERIFY(!fake->blobs.contains("Passwords.passwd"));
    QVERIFY(storage->ignoredPasswordReason(Location).isEmpty());
}

/// A vault stored encrypted by an older version is rewritten unencrypted,
/// and the user is told once.
void TestDeviceStorage::testEncryptedVaultIsRewrittenUnencrypted()
{
    saveNewDatabase("old");
    fake->encrypted.insert("Passwords.kdbx");
    yubiKeyChanged();
    QStringList notices;
    DeviceStorage::instance()->setNotice([&notices](const QString& message) { notices << message; });

    // It still opens, with the PIN.
    DeviceStorage::instance()->clearCache();
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(fake->fetches, 1);

    db->metadata()->setName("new");
    QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
    QVERIFY(!fake->encrypted.contains("Passwords.kdbx"));
    QCOMPARE(notices.size(), 1);
    QVERIFY(notices.first().contains("now stored unencrypted"));
    db->metadata()->setName("newer");
    QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
    QCOMPARE(notices.size(), 1);
}

/// A post-quantum store: a KDBX 4 vault opens with no PIN and no touch
/// (yb spec 0047 S4); saving asks for the FIDO2 PIN (named so) and one
/// touch, which the user is told about.
void TestDeviceStorage::testPostQuantumAsksFido2PinAndTouch()
{
    fake->kind = DeviceStorage::StoreKind::PostQuantum;
    DeviceStorage::instance()->clearCache(); // a reformat, for the caches
    QList<DeviceStorage::StoreKind> asked;
    DeviceStorage::instance()->setPinPrompt([&asked](const QString&, DeviceStorage::StoreKind kind) {
        asked << kind;
        return Pin;
    });
    int notices = 0;
    DeviceStorage::instance()->setTouchNotice([&notices] { ++notices; });
    saveNewDatabase("pq");
    QCOMPARE(asked, QList<DeviceStorage::StoreKind>{DeviceStorage::StoreKind::PostQuantum});
    QCOMPARE(fake->touches, 1);
    QCOMPARE(notices, 1);

    DeviceStorage::instance()->clearCache();
    DeviceStorage::instance()->forgetPin("");
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(db->metadata()->name(), QString("pq"));
    QCOMPARE(asked.size(), 1);
    QCOMPARE(fake->touches, 1);
    QCOMPARE(fake->fetches, 0);
    QCOMPARE(fake->unverifiedFetches, 1);
}

/// A locked YubiKey (post-quantum store).  A KDBX 4 vault opens anyway,
/// with no PIN and no question (yb spec 0047 S4).  A KDBX 3.1 vault needs
/// the full check, so it is read without it only if the user agrees, the
/// prompt being told it is KDBX 3.1 (yb spec 0044, 0046 S2).
void TestDeviceStorage::testLockedYubiKeyFallback()
{
    saveNewDatabase("locked");
    // The version in the header: minor, major (2 bytes each, little-endian).
    const auto setVersion = [](quint8 minor, quint8 major) {
        auto bytes = fake->blobs.value("Passwords.kdbx");
        bytes[8] = static_cast<char>(minor);
        bytes[9] = 0;
        bytes[10] = static_cast<char>(major);
        bytes[11] = 0;
        fake->blobs.insert("Passwords.kdbx", bytes);
        fake->generations.insert("Passwords.kdbx", fake->nextGeneration++);
        yubiKeyChanged();
        yubiKeyChanged();
    };
    fake->kind = DeviceStorage::StoreKind::PostQuantum;
    DeviceStorage::instance()->clearCache(); // a reformat, for the caches
    fake->locked = DeviceStorage::PinBlocked;
    int prompts = 0;
    bool sawKdbx3 = false;
    bool agree = false;
    DeviceStorage::instance()->setUnverifiedReadPrompt([&](const QString& blob, const QString& reason, bool kdbx3) {
        ++prompts;
        sawKdbx3 = kdbx3;
        return agree && blob == "Passwords.kdbx" && reason.contains("FIDO2 PIN is blocked");
    });

    // KDBX 4: opens, no question.
    setVersion(1, 4);
    QByteArray data;
    QString error;
    QVERIFY2(DeviceStorage::instance()->read(Location, &data, &error), qPrintable(error));
    QCOMPARE(prompts, 0);

    // KDBX 3.1: the full check fails on the locked YubiKey; the prompt.
    setVersion(1, 3);
    QVERIFY(!DeviceStorage::instance()->read(Location, &data, &error));
    QVERIFY2(error.contains("FIDO2 PIN is blocked"), qPrintable(error));
    QCOMPARE(prompts, 1);
    QVERIFY(sawKdbx3);
    agree = true;
    fake->generations.insert("Passwords.kdbx", fake->nextGeneration++);
    yubiKeyChanged();
    QVERIFY2(DeviceStorage::instance()->read(Location, &data, &error), qPrintable(error));
    QCOMPARE(prompts, 2);

    // An encrypted vault cannot be read without the PIN.
    fake->encrypted.insert("Passwords.kdbx");
    yubiKeyChanged();
    fake->generations.insert("Passwords.kdbx", fake->nextGeneration++);
    yubiKeyChanged();
    QVERIFY(!DeviceStorage::instance()->read(Location, &data, &error));
    QCOMPARE(prompts, 2);
}

/// A legacy store's vault opens without the PIN even when the PIN is
/// blocked: nothing to fall back from.
void TestDeviceStorage::testLegacyVaultOpensWithLockedYubiKey()
{
    saveNewDatabase("legacy");
    fake->locked = DeviceStorage::PinBlocked;
    DeviceStorage::instance()->clearCache();
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(db->metadata()->name(), QString("legacy"));
}

/// The master password is kept on the YubiKey, encrypted, only in a
/// post-quantum store (not on Windows yet).
void TestDeviceStorage::testRememberPassword()
{
    auto* storage = DeviceStorage::instance();
    QString error;
    QVERIFY(!storage->canRememberPassword(Location));
    QVERIFY(!storage->storePassword(Location, "secret", &error));
    QVERIFY(!fake->blobs.contains("Passwords.passwd"));

    fake->kind = DeviceStorage::StoreKind::PostQuantum;
    DeviceStorage::instance()->clearCache(); // a reformat, for the caches
#ifdef Q_OS_WIN
    QVERIFY(!storage->canRememberPassword(Location));
#else
    QVERIFY(storage->canRememberPassword(Location));
    QVERIFY2(storage->storePassword(Location, "secret", &error), qPrintable(error));
    QVERIFY(fake->encrypted.contains("Passwords.passwd"));
    QVERIFY(storage->hasStoredPassword(Location));
    QString password;
    QVERIFY(storage->readPassword(Location, &password, &error));
    QCOMPARE(password, QString("secret"));
#endif
}

/// Opening a vault reads the YubiKey once (yb spec 0050 S1): the unlock
/// dialog's refresh serves its questions, the header read, and the unlock.
void TestDeviceStorage::testOneReadToOpen()
{
    saveNewDatabase("one read");
    fake->kind = DeviceStorage::StoreKind::PostQuantum;
    fake->blobs.insert("Passwords.passwd", "secret");
    yubiKeyChanged();
    auto* storage = DeviceStorage::instance();
    storage->clearCache();
    // As after a lock: the PIN is forgotten before the locked view loads.
    storage->forgetPin("");
    fake->refreshes = 0;

    QString error;
    QVERIFY(storage->refresh({}, &error));
    QSharedPointer<Database>::create()->open(Location, nullptr, &error);
    const auto status = storage->passwordStatus(Location);
    QVERIFY(!status.used);
    QVERIFY(!status.ignoredReason.isEmpty());
    auto db = QSharedPointer<Database>::create();
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(fake->refreshes, 1);
    // The header read of a KDBX 4 vault reads it without the PIN (S4).
    QCOMPARE(fake->fetches, 0);
    QCOMPARE(fake->unverifiedFetches, 1);
}

/// Questions are answered from the snapshot until a refresh; KeePassYB's
/// own writes keep it up to date (yb spec 0050 S1).
void TestDeviceStorage::testSnapshotUntilRefresh()
{
    auto* storage = DeviceStorage::instance();
    saveNewDatabase("first");
    QString error;
    QCOMPARE(storage->listVaults({}, &error), QStringList({"Passwords.kdbx"}));

    // Another program stores a vault: not seen until a refresh.
    fake->blobs.insert("Other.kdbx", "x");
    QVERIFY(!storage->listVaults({}, &error).contains("Other.kdbx"));
    QVERIFY(storage->refresh({}, &error));
    QVERIFY(storage->listVaults({}, &error).contains("Other.kdbx"));

    // A vault missing from the snapshot is looked for again.
    fake->blobs.insert("Late.kdbx", fake->blobs.value("Passwords.kdbx"));
    QByteArray data;
    QVERIFY2(storage->read(DeviceStorage::location({}, "Late.kdbx"), &data, &error), qPrintable(error));
}

/// A save is one store call: no listing or refresh reads the YubiKey
/// around it (yb spec 0050 S1).
void TestDeviceStorage::testSaveIsOneStoreCall()
{
    saveNewDatabase("save");
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    fake->refreshes = 0;
    const auto stores = fake->stores;
    db->metadata()->setName("saved");
    QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
    QCOMPARE(fake->stores, stores + 1);
    QCOMPARE(fake->refreshes, 0);
}

/// A vault changed on the YubiKey since it was opened is not overwritten:
/// the save fails, writing nothing, and asks the user (KeePassXC's merge,
/// as for a file changed on disk); Overwrite then writes it (yb spec 0050
/// S3).
void TestDeviceStorage::testChangedOnTheYubiKey()
{
    saveNewDatabase("mine");
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));

    // Another program saves the vault meanwhile: its own session, so
    // KeePassYB's snapshot does not see it.
    const auto snapBlobs = fake->snapBlobs;
    const auto snapGenerations = fake->snapGenerations;
    auto theirs = QSharedPointer<Database>::create();
    QVERIFY2(theirs->open(Location, key(), &error), qPrintable(error));
    theirs->metadata()->setName("theirs");
    QVERIFY2(theirs->save(Database::Atomic, {}, &error), qPrintable(error));
    fake->snapBlobs = snapBlobs;
    fake->snapGenerations = snapGenerations;
    const auto onCard = fake->blobs.value("Passwords.kdbx");

    QSignalSpy asked(db.data(), &Database::databaseFileChanged);
    db->metadata()->setName("mine again");
    QVERIFY(!db->save(Database::Atomic, {}, &error));
    QVERIFY2(error.contains("changed on the YubiKey"), qPrintable(error));
    QCOMPARE(fake->blobs.value("Passwords.kdbx"), onCard);
    QVERIFY(db->isModified());
    QTRY_COMPARE(asked.count(), 1);
    QCOMPARE(asked.first().first().toBool(), true);

    // Overwrite.
    db->setIgnoreFileChangesUntilSaved(true);
    QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
    QVERIFY(fake->blobs.value("Passwords.kdbx") != onCard);
    QVERIFY(!db->ignoreFileChangesUntilSaved());
}

/// While quitting, reads and questions do not reach the YubiKey; a write
/// still does.
void TestDeviceStorage::testNothingReachesTheYubiKeyWhenQuitting()
{
    saveNewDatabase("quit");
    auto* storage = DeviceStorage::instance();
    storage->clearCache();
    storage->setQuitting(true);
    fake->lists = 0;
    fake->kinds = 0;

    QByteArray data;
    QString error;
    QVERIFY(!storage->read(Location, &data, &error));
    QVERIFY(storage->listVaults({}, &error).isEmpty());
    QVERIFY(!storage->passwordStatus(Location).used);
    QString password;
    QVERIFY(storage->readPassword(Location, &password, &error));
    QCOMPARE(fake->lists + fake->kinds, 0);

    const auto stores = fake->stores;
    QVERIFY2(storage->write(Location, "bytes", &error), qPrintable(error));
    QCOMPARE(fake->stores, stores + 1);
}

/// Called from the GUI (main) thread, the YubiKey is reached from a worker
/// thread: the GUI keeps processing events.
void TestDeviceStorage::testOperationsRunOffTheGuiThread()
{
    saveNewDatabase("threads");
    DeviceStorage::instance()->clearCache();
    fake->calledOnMainThread = false;
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    DeviceStorage::instance()->passwordStatus(Location);
    DeviceStorage::instance()->listVaults({}, &error);
    QVERIFY(!fake->calledOnMainThread);
}

/// A slow operation reports its progress: what it does, the touch it
/// waits for, then its end (yb spec 0047 S4).
void TestDeviceStorage::testProgress()
{
    fake->kind = DeviceStorage::StoreKind::PostQuantum;
    DeviceStorage::instance()->clearCache(); // a reformat, for the caches
    QStringList shown;
    // "!": shown at once (a touch, yb spec 0051 S5).
    DeviceStorage::instance()->setProgress(
        [&shown](const QString& text, bool now) { shown << (now ? "!" + text : text); });
    // The PIN prompt is not shown under the (modal) progress dialog: it is
    // hidden first, and comes back after.
    DeviceStorage::instance()->setPinPrompt([&shown](const QString&, DeviceStorage::StoreKind) {
        shown << "PIN?";
        return Pin;
    });
    saveNewDatabase("progress");
    DeviceStorage::instance()->setProgress({});
    QCOMPARE(shown,
             QStringList({"Saving Passwords.kdbx to the YubiKey…",
                          QString(),
                          "PIN?",
                          "Saving Passwords.kdbx to the YubiKey…",
                          "!Touch your YubiKey to save Passwords.kdbx.",
                          "Saving Passwords.kdbx to the YubiKey…",
                          QString()}));
}

/// The unchanged-content check (yb spec 0047 S2): a vault marked modified
/// whose content is the same as when it was read counts as unchanged; the
/// view's state (an expanded group) does not count; a real change does.
void TestDeviceStorage::testUnchangedContentIsDetected()
{
    saveNewDatabase("content");
    DeviceStorage::instance()->clearCache();
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QVERIFY(db->deviceContentUnchanged());

    db->markAsModified();
    QVERIFY(db->deviceContentUnchanged());

    db->rootGroup()->setExpanded(!db->rootGroup()->isExpanded());
    db->metadata()->setLastSelectedGroup(db->rootGroup());
    QVERIFY(db->deviceContentUnchanged());

    db->metadata()->setName("changed");
    QVERIFY(!db->deviceContentUnchanged());

    // Saved: the new content is the reference.
    QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
    QVERIFY(db->deviceContentUnchanged());
}

/// A change another program made that a refresh has already brought into
/// the snapshot (another dialog opened meanwhile) is a conflict all the
/// same: the database is based on an older version (yb spec 0050 S3).
void TestDeviceStorage::testChangeSeenByARefreshIsStillAConflict()
{
    saveNewDatabase("mine");
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));

    auto theirs = QSharedPointer<Database>::create();
    QVERIFY2(theirs->open(Location, key(), &error), qPrintable(error));
    theirs->metadata()->setName("theirs");
    QVERIFY2(theirs->save(Database::Atomic, {}, &error), qPrintable(error));
    QVERIFY(DeviceStorage::instance()->refresh({}, &error));
    const auto onCard = fake->blobs.value("Passwords.kdbx");

    QSignalSpy asked(db.data(), &Database::databaseFileChanged);
    db->metadata()->setName("mine again");
    QVERIFY(!db->save(Database::Atomic, {}, &error));
    QVERIFY2(error.contains("changed on the YubiKey"), qPrintable(error));
    QCOMPARE(fake->blobs.value("Passwords.kdbx"), onCard);
    QTRY_COMPARE(asked.count(), 1);
}

/// The written copy has no random padding unless the vault uses KeeShare,
/// whose size side channel it defends against (yb spec 0051 S2).
void TestDeviceStorage::testPaddingOnlyWithKeeShare()
{
    saveNewDatabase("padding");
    QString error;
    auto reopened = [&] {
        DeviceStorage::instance()->clearCache();
        auto db = QSharedPointer<Database>::create();
        db->open(Location, key(), &error);
        return db;
    };
    auto db = reopened();
    QVERIFY2(db->isInitialized(), qPrintable(error));
    QVERIFY(!db->metadata()->customData()->contains(CustomData::RandomSlug));

    auto* shared = new Group();
    shared->setUuid(QUuid::createUuid());
    shared->setName("shared");
    shared->setParent(db->rootGroup());
    shared->customData()->set("KeeShare/Reference", "x");
    QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
    QVERIFY(reopened()->metadata()->customData()->contains(CustomData::RandomSlug));
}

/// A vault first saved to a YubiKey keeps no old versions of its entries
/// (the user is told, and may raise the setting); one already there keeps
/// its setting (yb spec 0051 S4).
void TestDeviceStorage::testNoHistoryWhenFirstSavedToAYubiKey()
{
    QStringList notices;
    DeviceStorage::instance()->setNotice([&notices](const QString& message) { notices << message; });
    auto db = QSharedPointer<Database>::create();
    auto kdf = KeePass2::uuidToKdf(KeePass2::KDF_ARGON2D);
    kdf->setRounds(1);
    kdf->processParameters({{KeePass2::KDFPARAM_ARGON2_MEMORY, 1024}, {KeePass2::KDFPARAM_ARGON2_PARALLELISM, 1}});
    db->changeKdf(kdf);
    db->setKey(key());
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("with history");
    entry->setGroup(db->rootGroup());
    entry->addHistoryItem(entry->clone(Entry::CloneNoFlags));
    QCOMPARE(entry->historyItems().size(), 1);

    QString error;
    QVERIFY2(db->saveAs(Location, Database::Atomic, {}, &error), qPrintable(error));
    QCOMPARE(db->metadata()->historyMaxItems(), 0);
    QVERIFY(entry->historyItems().isEmpty());
    QCOMPARE(notices.size(), 1);
    QVERIFY2(notices.first().contains("History"), qPrintable(notices.first()));

    db->metadata()->setHistoryMaxItems(5);
    QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
    QCOMPARE(db->metadata()->historyMaxItems(), 5);
    QCOMPARE(notices.size(), 1);
    DeviceStorage::instance()->setNotice({});
}
