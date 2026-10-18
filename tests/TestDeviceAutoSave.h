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

#ifndef KEEPASSXC_TESTDEVICEAUTOSAVE_H
#define KEEPASSXC_TESTDEVICEAUTOSAVE_H

#include <QObject>
#include <QPointer>
#include <QSharedPointer>
#include <QUuid>

class Database;
class DatabaseWidget;
class Group;

/// Automatic saves of a vault on a YubiKey (yb spec 0050 S2), on a
/// DatabaseWidget over the in-memory YubiKey of mock/FakeDeviceBackend.h.
class TestDeviceAutoSave : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void init();
    void cleanup();
    void cleanupTestCase();

    void testAutoSaveAfterQuietDelay();
    void testNoAutoSaveForViewChanges();
    void testFailedAutoSaveDoesNotRetry();
    void testYubiKeyOperationPostponesSave();
    void testSaveRequestsMakeOneWrite();
    void testLockSavesWithoutAsking();
    void testLockAsksWhenAutoSaveOnExitIsOff();
    void testChangedOnTheYubiKeyAsks();
    void testViewStateGoesAlongWithAChange();
    void testAutoSaveSkipsPresentation();
    void testSaveWritesPresentation();
    void testLockWritesPresentation();
    void testLockLeavesPresentationWhenSettingIsOff();
    void testPresentationRevertedIsNotWritten();
    void testPresentationSaveFailureDoesNotStopLock();

private:
    void change(const QString& title, bool waitForReport = true);
    void nothingStoredFor(int ms);
    Group* savedFoldedGroup();
    bool rereadExpanded(const QUuid& uuid);

    QSharedPointer<Database> m_db;
    QPointer<DatabaseWidget> m_widget;
};

#endif // KEEPASSXC_TESTDEVICEAUTOSAVE_H
