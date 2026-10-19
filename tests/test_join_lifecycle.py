#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause-Clear
"""Run the driver's actual join mailbox and supervisor with a simulated radio.

The extracted methods are compiled unchanged. Only their IOKit, clock and radio
dependencies are mocked; no hardware, credentials or installed driver is used.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def extract_function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


HARNESS = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>
#include <strings.h>

using IOReturn = int;
static const IOReturn kIOReturnSuccess = 0, kIOReturnNotReady = -1;
enum { ITL_NATIVE_IDLE = 0, ITL_NATIVE_UP = 2, ITL_NATIVE_FAILED = 3 };
struct OSBoolean { bool value; };
static const OSBoolean trueObject = {true}, falseObject = {false};
static const OSBoolean *kOSBooleanTrue = &trueObject, *kOSBooleanFalse = &falseObject;
static size_t test_strlcpy(char *dest, const char *source, size_t size) {
    const size_t length = std::strlen(source);
    if (size) {
        const size_t copied = length < size - 1 ? length : size - 1;
        std::memcpy(dest, source, copied);
        dest[copied] = 0;
    }
    return length;
}
#define strlcpy test_strlcpy
struct IOLock { bool held = false; std::function<void()> onAcquire; };
static void IOLockLock(IOLock *lock) {
    assert(lock && !lock->held);
    lock->held = true;
    if (lock->onAcquire) {
        auto hook = lock->onAcquire;
        lock->onAcquire = nullptr;
        hook();
    }
}
static void IOLockUnlock(IOLock *lock) { assert(lock && lock->held); lock->held = false; }

class itlmt7922;
static itlmt7922 *activeDriver;
static uint32_t nowMs();
static void IOSleep(uint32_t milliseconds);

class itlmt7922 {
public:
    enum { CMD_SCAN = 1, CMD_JOIN = 2, CMD_DISCONNECT = 4 };
    struct Net { char ssid[33]; char psk[72]; bool hasPmk; bool native; uint8_t pmk[32]; };
    IOLock storage;
    IOLock *cmdLock = &storage;
    volatile uint32_t cmdBits = 0;
    Net reqNet = {}, candNets[4] = {};
    bool userJoinPending = false, userJoinStopped = false;
    char userJoinSsid[33] = {}, m3ssid[33] = {};
    bool m3On = true, stopping = false, firmwareFault = false;
    char wstate[32] = "idle", capSsid[33] = {};
    char m3lostWhy[128] = {}, m3res[128] = "auth-fail";
    uint32_t capMs = 0, linkUpMs = 0, clockMs = 1, recoverCnt = 0;
    uint8_t lvlCap = 255, capBand = 0;
    bool recoverWanted = false, m3lost = false, m3linkUp = false, m3reachedAssoc = true;
    int candN = 0, njState = ITL_NATIVE_IDLE, njFail = 0;

    bool joinPending = false, joinSucceeded = false, recoverResult = false;
    unsigned propertyWrites = 0, attempts = 0, scans = 0, backoffPumps = 0, terminalChecks = 0;
    unsigned recoverCalls = 0;
    bool cancelQueued = false, inRange = true;
    std::string scenario;
    std::vector<uint32_t> attemptTimes;
    std::vector<bool> scanPending;

    IOReturn ucJoin(const char *, const char *);
    IOReturn ucDisconnect();
    uint32_t cmdTake(uint32_t, Net *);
    void finishUserJoin(bool stopped = false, bool succeeded = false);
    void m3Supervise();
    bool shouldStop() const { return stopping; }
    bool cmdPending(uint32_t mask) const { return (__atomic_load_n(&cmdBits, __ATOMIC_ACQUIRE) & mask) != 0; }
    void setProperty(const char *key, const OSBoolean *value) {
        assert(cmdLock->held); // Pending/result must be published while the mailbox is serialized.
        ++propertyWrites;
        if (!std::strcmp(key, "wifi-join-pending")) joinPending = value->value;
        else if (!std::strcmp(key, "wifi-join-succeeded")) joinSucceeded = value->value;
        else assert(false && "unexpected Boolean property");
    }
    void setProperty(const char *, const char *) {}
    int loadPlistNets(Net *, int) { return 0; }
    void wifiNets() {}
    void wifiState(const char *state, const char *) { strlcpy(wstate, state, sizeof(wstate)); }
    void m3log(const char *, ...) {}
    void evLog(const char *, ...) {}
    void ethLink(bool) {}
    bool chipRecover() { ++recoverCalls; return recoverResult; }
    bool apInRange(const char *, uint32_t) { return inRange; }
    int failCode(const char *) { return 1; }
    const char *failText(const char *) { return "connection failed"; }
    void wifiScan() {
        ++scans;
        scanPending.push_back(joinPending);
        assert(joinPending && userJoinPending && !joinSucceeded);
    }
    int m3Run() {
        assert(joinPending && userJoinPending && !joinSucceeded);
        assert(candN == 1 && !std::strcmp(candNets[0].ssid, "SyntheticAP"));
        ++attempts;
        assert(attempts <= 3);
        attemptTimes.push_back(clockMs);
        return -1; // A failed attempt is retried by the real supervisor below.
    }
    void m3PumpOnce() {
        if (scenario == "retry") {
            if (attempts < 3) {
                assert(joinPending && userJoinPending && !joinSucceeded);
                ++backoffPumps;
            } else {
                assert(!joinPending && !userJoinPending && !joinSucceeded);
                ++terminalChecks;
                stopping = true;
            }
        } else if (scenario == "cancel") {
            assert(attempts == 1);
            if (!cancelQueued) {
                assert(joinPending && !joinSucceeded);
                assert(ucDisconnect() == kIOReturnSuccess);
                assert(!joinPending && !joinSucceeded);
                cancelQueued = true;
            } else if (!(cmdBits & CMD_DISCONNECT)) {
                assert(!joinPending && !userJoinPending && !joinSucceeded);
                ++terminalChecks;
                stopping = true;
            }
        } else assert(false && "unexpected idle supervisor iteration");
    }
};

static uint32_t nowMs() { assert(activeDriver); return activeDriver->clockMs; }
static void IOSleep(uint32_t milliseconds) {
    assert(activeDriver);
    activeDriver->clockMs += milliseconds;
    assert(activeDriver->clockMs < 20000); // A broken retry/terminal transition must fail instead of hanging.
}

%FUNCTIONS%

static void queue(itlmt7922 &driver, const char *ssid = "SyntheticAP") {
    assert(driver.ucJoin(ssid, "synthetic-test-password") == kIOReturnSuccess);
    assert(driver.joinPending && driver.userJoinPending && !driver.joinSucceeded);
    assert(!driver.storage.held);
}

static void take(itlmt7922 &driver, const char *ssid = "SyntheticAP") {
    itlmt7922::Net request = {};
    assert(driver.cmdTake(itlmt7922::CMD_JOIN, &request) == itlmt7922::CMD_JOIN);
    assert(!std::strcmp(request.ssid, ssid));
    assert(!std::strcmp(request.psk, "synthetic-test-password"));
    const itlmt7922::Net empty = {};
    assert(!std::memcmp(&driver.reqNet, &empty, sizeof(empty)));
    assert(driver.joinPending && driver.userJoinPending && !driver.joinSucceeded);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const std::string test = argv[1];
    itlmt7922 driver;
    activeDriver = &driver;
    if (test == "accepted-and-completed") {
        queue(driver);
        take(driver);
        strlcpy(driver.m3ssid, "SyntheticAP", sizeof(driver.m3ssid));
        driver.finishUserJoin(false, true);
        assert(!driver.joinPending && !driver.userJoinPending && driver.joinSucceeded);
        driver.finishUserJoin();
        assert(driver.joinSucceeded); // A later idle/exit path cannot erase a completed result.
    } else if (test == "newer-queued-join") {
        queue(driver); take(driver);
        queue(driver, "NewerAP");
        strlcpy(driver.m3ssid, "SyntheticAP", sizeof(driver.m3ssid));
        const auto writes = driver.propertyWrites;
        driver.finishUserJoin(false, true);
        assert(driver.joinPending && driver.userJoinPending && !driver.joinSucceeded);
        assert(driver.propertyWrites == writes);
        assert(!std::strcmp(driver.reqNet.ssid, "NewerAP"));
        take(driver, "NewerAP");
        strlcpy(driver.m3ssid, "NewerAP", sizeof(driver.m3ssid));
        driver.finishUserJoin(false, true);
        assert(!driver.joinPending && driver.joinSucceeded);
    } else if (test == "failed-then-automatic-success") {
        queue(driver); take(driver);
        driver.finishUserJoin();
        assert(!driver.joinPending && !driver.joinSucceeded);
        strlcpy(driver.m3ssid, "SyntheticAP", sizeof(driver.m3ssid));
        driver.finishUserJoin(false, true);
        assert(!driver.joinPending && !driver.joinSucceeded); // Same SSID, unrelated boot credentials.
    } else if (test == "different-network-success") {
        queue(driver); take(driver);
        strlcpy(driver.m3ssid, "OtherConfiguredAP", sizeof(driver.m3ssid));
        driver.finishUserJoin(false, true);
        assert(!driver.joinPending && !driver.userJoinPending && !driver.joinSucceeded);
        strlcpy(driver.m3ssid, "SyntheticAP", sizeof(driver.m3ssid));
        driver.finishUserJoin(false, true);
        assert(!driver.joinSucceeded); // A later automatic connection cannot adopt the old request.
    } else if (test == "cancel-command") {
        queue(driver);
        assert(driver.ucDisconnect() == kIOReturnSuccess);
        assert(!driver.joinPending && !driver.userJoinPending && !driver.joinSucceeded);
        assert(!(driver.cmdBits & itlmt7922::CMD_JOIN));
        assert(driver.cmdBits & itlmt7922::CMD_DISCONNECT);
        strlcpy(driver.m3ssid, "SyntheticAP", sizeof(driver.m3ssid));
        driver.finishUserJoin(false, true);
        assert(!driver.joinSucceeded);
    } else if (test == "lock-race-stop" || test == "lock-race-worker-exit") {
        driver.storage.onAcquire = [&driver, &test] {
            if (test == "lock-race-stop") driver.stopping = true;
            else driver.userJoinStopped = true;
        };
        assert(driver.ucJoin("SyntheticAP", "synthetic-test-password") == kIOReturnNotReady);
        assert(!driver.joinPending && !driver.userJoinPending && !driver.cmdBits);
        assert(driver.propertyWrites == 0 && !driver.storage.held);
    } else if (test == "retry" || test == "cancel") {
        queue(driver);
        driver.scenario = test;
        driver.m3Supervise();
        assert(driver.userJoinStopped && !driver.joinPending && !driver.joinSucceeded);
        assert(driver.terminalChecks == 1);
        if (test == "retry") {
            assert(driver.attempts == 3 && driver.scans == 2 && driver.backoffPumps > 0);
            assert(driver.attemptTimes[1] - driver.attemptTimes[0] >= 3000);
            assert(driver.attemptTimes[2] - driver.attemptTimes[1] >= 5000);
            for (bool pending : driver.scanPending) assert(pending);
        } else assert(driver.attempts == 1 && driver.cancelQueued);
    } else if (test == "fatal-exhausted" || test == "fatal-recovery-failed" || test == "stopped") {
        queue(driver);
        if (test == "stopped") driver.stopping = true;
        else {
            driver.firmwareFault = true;
            if (test == "fatal-exhausted") driver.recoverCnt = 8;
        }
        driver.m3Supervise();
        assert(!driver.joinPending && !driver.userJoinPending && !driver.joinSucceeded);
        assert(driver.userJoinStopped && driver.attempts == 0);
        assert(driver.recoverCalls == (test == "fatal-recovery-failed" ? 1u : 0u));
        driver.stopping = false;
        assert(driver.ucJoin("SyntheticAP", "synthetic-test-password") == kIOReturnNotReady);
        assert(driver.ucDisconnect() == kIOReturnNotReady);
        assert(!driver.joinPending);
    } else assert(false && "unknown case");
    assert(!driver.storage.held);
}
'''


class JoinLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / 'src/itlmt7922_uc.cpp').read_text()
        functions = '\n\n'.join(extract_function(source, signature) for signature in (
            'IOReturn itlmt7922::ucJoin(',
            'IOReturn itlmt7922::ucDisconnect(',
            'uint32_t itlmt7922::cmdTake(',
            'void itlmt7922::finishUserJoin(',
            'void itlmt7922::m3Supervise(',
        ))
        cls.directory = tempfile.TemporaryDirectory(prefix='mt7922-join-lifecycle-')
        cls.addClassCleanup(cls.directory.cleanup)
        directory = Path(cls.directory.name)
        cpp = directory / 'join_lifecycle.cpp'
        cpp.write_text(HARNESS.replace('%FUNCTIONS%', functions))
        cls.binary = directory / 'join_lifecycle'
        compiler = shlex.split(os.environ.get('CXX', 'c++'))
        subprocess.run(compiler + [
            '-std=c++11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
            str(cpp), '-o', str(cls.binary),
        ], check=True)

    def run_case(self, case):
        subprocess.run([str(self.binary), case], check=True)

    def test_acceptance_and_terminal_results(self):
        for case in ('accepted-and-completed', 'failed-then-automatic-success',
                     'different-network-success', 'cancel-command'):
            with self.subTest(case=case):
                self.run_case(case)

    def test_old_completion_preserves_new_queued_request(self):
        self.run_case('newer-queued-join')

    def test_request_rechecks_worker_availability_under_lock(self):
        for case in ('lock-race-stop', 'lock-race-worker-exit'):
            with self.subTest(case=case):
                self.run_case(case)

    def test_supervisor_keeps_pending_through_scan_and_backoff_then_gives_up(self):
        self.run_case('retry')

    def test_supervisor_obeys_cancellation(self):
        self.run_case('cancel')

    def test_supervisor_terminal_exits_clear_pending_and_reject_new_joins(self):
        for case in ('fatal-exhausted', 'fatal-recovery-failed', 'stopped'):
            with self.subTest(case=case):
                self.run_case(case)

    def test_success_completion_is_published_at_actual_link_boundary(self):
        source = (ROOT / 'src/itlmt7922_m3.cpp').read_text()
        link = extract_function(source, 'void itlmt7922::m3Link(')
        connected = link.index('wifiState("connected", "")')
        published = link.index('wifiLink()', connected)
        completed = link.index('finishUserJoin(false, true)', published)
        self.assertGreater(completed, published)


if __name__ == '__main__':
    unittest.main()
