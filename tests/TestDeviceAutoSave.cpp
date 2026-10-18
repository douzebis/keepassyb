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

#include "TestDeviceAutoSave.h"

#include <QSignalSpy>
#include <QTimer>

#include "core/Config.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "crypto/Crypto.h"
#include "gui/Application.h"
#include "gui/DatabaseWidget.h"
#include "gui/MessageBox.h"
#include "keeshare/KeeShare.h"
#include "mock/FakeDeviceBackend.h"
#include "util/TemporaryFile.h"

// KeePassXC's Application, which its widgets expect (as in TestGui).
int main(int argc, char* argv[])
{
    Application app(argc, argv);
    app.setApplicationName("KeePassXC");
    app.setQuitOnLastWindowClosed(false);
    app.applyTheme();
    TestDeviceAutoSave tc;
    QTEST_SET_MAIN_SOURCE_PATH
    return QTest::qExec(&tc, argc, argv);
}

using namespace fakedevice;

void TestDeviceAutoSave::initTestCase()
{
    QVERIFY(Crypto::init());
    Config::createConfigFromFile(TemporaryFile::createTempConfigFile(), {});
    Application::bootstrap();
    // As MainWindow does: a DatabaseWidget's group editor needs it.
    KeeShare::init(this);
}

void TestDeviceAutoSave::init()
{
    config()->resetToDefaults();
    // KeePassXC's defaults, which a vault on a YubiKey follows.
    config()->set(Config::AutoSaveAfterEveryChange, true);
    config()->set(Config::AutoSaveOnExit, true);
    config()->set(Config::UseAtomicSaves, false);

    delete fake;
    fake = new FakeDevice;
    auto* storage = DeviceStorage::instance();
    storage->setBackend(std::make_unique<FakeBackend>());
    storage->setPinPrompt([](const QString&, DeviceStorage::StoreKind) { return Pin; });
    storage->setNotice({});
    storage->clearCache();
    storage->setQuitting(false);
    storage->forgetPin("");

    saveNewDatabase("automatic");
    m_db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(m_db->open(Location, key(), &error), qPrintable(error));
    m_widget = new DatabaseWidget(m_db);
}

void TestDeviceAutoSave::cleanup()
{
    MessageBox::setNextAnswer(MessageBox::NoButton);
    delete m_widget;
    m_db.reset();
}

void TestDeviceAutoSave::cleanupTestCase()
{
    DeviceStorage::instance()->setBackend(nullptr);
    DeviceStorage::instance()->setPinPrompt({});
    delete fake;
    fake = nullptr;
}

/// A data change: a new entry, once the database has told so (its
/// `modified` signal comes after a short delay).
void TestDeviceAutoSave::change(const QString& title)
{
    QSignalSpy told(m_db.data(), &Database::modified);
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle(title);
    entry->setGroup(m_db->rootGroup());
    QTRY_VERIFY(!told.isEmpty());
}

/// The quiet delay ends (its timer's slot, rather than waiting for it).
void TestDeviceAutoSave::quietDelayEnds()
{
    QVERIFY(QMetaObject::invokeMethod(m_widget, "onDeviceSaveDelayTimeout"));
}

/// The device save timer is running: at least 10 s, restarted by changes.
bool TestDeviceAutoSave::savePending() const
{
    for (const auto* timer : m_widget->findChildren<QTimer*>()) {
        if (timer->isActive() && timer->isSingleShot() && timer->interval() >= 10000) {
            return true;
        }
    }
    return false;
}

/// A burst of changes makes one save, once the changes pause (yb spec
/// 0050 S2).
void TestDeviceAutoSave::testAutoSaveAfterQuietDelay()
{
    const auto stores = fake->stores;
    change("one");
    change("two");
    change("three");
    QTRY_VERIFY(savePending());
    QCOMPARE(fake->stores, stores);
    quietDelayEnds();
    QCOMPARE(fake->stores, stores + 1);
    QVERIFY(!m_db->isModified());
}

/// A database marked modified, its content unchanged (a change of view):
/// nothing is written, and it is clean again.
void TestDeviceAutoSave::testNoAutoSaveForViewChanges()
{
    const auto attempts = fake->storeAttempts;
    m_db->rootGroup()->setExpanded(!m_db->rootGroup()->isExpanded());
    m_db->markAsModified();
    QTRY_VERIFY(savePending());
    quietDelayEnds();
    QCOMPARE(fake->storeAttempts, attempts);
    QVERIFY(!m_db->isModified());
}

/// A failed automatic save (a touch refused) is not retried until the
/// next change: no loop of prompts.
void TestDeviceAutoSave::testFailedAutoSaveDoesNotRetry()
{
    fake->locked = DeviceStorage::NoTouch;
    const auto attempts = fake->storeAttempts;
    change("refused");
    QTRY_VERIFY(savePending());
    quietDelayEnds();
    QCOMPARE(fake->storeAttempts, attempts + 1);
    QVERIFY(m_db->isModified());
    quietDelayEnds();
    QCOMPARE(fake->storeAttempts, attempts + 1);

    fake->locked = DeviceStorage::Ok;
    change("accepted");
    QTRY_VERIFY(savePending());
    quietDelayEnds();
    QCOMPARE(fake->storeAttempts, attempts + 2);
    QVERIFY(!m_db->isModified());
}

/// Lock with automatic saves on: saved without asking.
void TestDeviceAutoSave::testLockSavesWithoutAsking()
{
    const auto stores = fake->stores;
    change("before lock");
    // Were a question asked, it would be cancelled, and the lock refused.
    MessageBox::setNextAnswer(MessageBox::Cancel);
    QVERIFY(m_widget->lock());
    QCOMPARE(fake->stores, stores + 1);
}

/// Lock with automatic saves off: "Save changes?", as in spec 0047.
void TestDeviceAutoSave::testLockAsksWhenAutoSaveOnExitIsOff()
{
    config()->set(Config::AutoSaveAfterEveryChange, false);
    config()->set(Config::AutoSaveOnExit, false);
    const auto stores = fake->stores;
    change("before lock");
    QVERIFY(!savePending());
    MessageBox::setNextAnswer(MessageBox::Save);
    QVERIFY(m_widget->lock());
    QCOMPARE(fake->stores, stores + 1);
}

/// The vault changed on the YubiKey since it was opened: the automatic
/// save writes nothing and asks, as for a file changed on disk; Overwrite
/// writes it (yb spec 0050 S3).
void TestDeviceAutoSave::testChangedOnTheYubiKeyAsks()
{
    // Another program saves the vault meanwhile: its own session.
    const auto snapBlobs = fake->snapBlobs;
    const auto snapGenerations = fake->snapGenerations;
    auto theirs = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(theirs->open(Location, key(), &error), qPrintable(error));
    theirs->metadata()->setName("theirs");
    QVERIFY2(theirs->save(Database::Atomic, {}, &error), qPrintable(error));
    fake->snapBlobs = snapBlobs;
    fake->snapGenerations = snapGenerations;
    const auto stores = fake->stores;
    const auto onCard = fake->blobs.value("Passwords.kdbx");

    change("mine");
    QTRY_VERIFY(savePending());
    MessageBox::setNextAnswer(MessageBox::Overwrite);
    quietDelayEnds();
    QCOMPARE(fake->blobs.value("Passwords.kdbx"), onCard);
    QTRY_COMPARE(fake->stores, stores + 1);
    QVERIFY(fake->blobs.value("Passwords.kdbx") != onCard);
}
