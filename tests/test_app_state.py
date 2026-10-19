#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause-Clear
"""Run the real Swift status/model/login methods with isolated driver and storage stubs.

Only Foundation is loaded. No IOKit service, password store or real LaunchAgent is
accessed; plist writes are restricted to a temporary test directory.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "app/ItlWiFi7922.swift").read_text()


def block(marker):
    """Extract a production declaration, including its balanced body."""
    start = SOURCE.index(marker)
    brace = SOURCE.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (SOURCE[end] == "{") - (SOURCE[end] == "}")
        end += 1
    return SOURCE[start:end]


TYPES = block("struct WifiNet {") + "\n" + block("struct WifiStatus {")


class AppStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("xcrun"):
            cls.swift = ["xcrun", "swiftc"]
        elif shutil.which("swiftc"):
            cls.swift = ["swiftc"]
        else:
            raise unittest.SkipTest("Swift compiler is required for App regression tests")

    def run_swift(self, body):
        with tempfile.TemporaryDirectory(prefix="itlmt7922-app-tests-") as directory:
            temp = Path(directory)
            source, executable = temp / "test.swift", temp / "test"
            source.write_text("import Foundation\n" + body)
            compile_result = subprocess.run(
                self.swift + ["-module-cache-path", str(temp / "cache"),
                              str(source), "-o", str(executable)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(compile_result.returncode, 0, compile_result.stdout)
            result = subprocess.run([str(executable)], cwd=temp, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(result.returncode, 0, result.stdout)
            return result.stdout

    def test_status_lifecycle_property_and_read_order(self):
        status = block("static func status() -> WifiStatus")
        self.run_swift(TYPES + r'''
typealias CFString = String
let kCFAllocatorDefault = 0
var properties: [String: Any] = [:]
var reads: [String] = []
struct Property { let value: Any; func takeRetainedValue() -> Any { value } }
enum Driver {
    static var available = true
    static func service() -> UInt32 { available ? 1 : 0 }
    static func IOObjectRelease(_ service: UInt32) {}
    static func IORegistryEntryCreateCFProperty(_ service: UInt32, _ key: String, _ allocator: Int, _ flags: Int) -> Property? {
        reads.append(key)
        return properties[key].map { Property(value: $0) }
    }
''' + status + r'''
}
for flag in [true, false] {
    properties = ["wifi-join-pending": NSNumber(value: flag), "wifi-join-succeeded": NSNumber(value: !flag),
                  "wifi-state": "connected", "wifi-ssid": "TestAP"]
    reads = []
    let status = Driver.status()
    precondition(status.joinPending == flag && status.joinSucceeded == !flag && status.ssid == "TestAP")
    precondition(Array(reads.prefix(3)) == ["wifi-join-pending", "wifi-join-succeeded", "wifi-state"],
                 "Lifecycle flags must be sampled before the link state")
}
properties = ["wifi-state": "failed"]
precondition(Driver.status().joinPending == nil && Driver.status().joinSucceeded == nil,
             "Older kexts must stay distinguishable from false")
Driver.available = false
precondition(!Driver.status().present && Driver.status().joinPending == nil)
''')

    def test_model_join_lifecycle(self):
        field_start = SOURCE.index("{", SOURCE.index("final class WifiModel:")) + 1
        fields = SOURCE[field_start:SOURCE.index("\n    init() {", field_start)]
        fields = fields.replace("@Published ", "").replace("private var ", "var ")
        methods = "\n".join(block(marker) for marker in [
            "var connected: Bool", "var busy: Bool", "var connectingSSID: String?",
            "func refresh()", "func join(_ ssid:", "func disconnect()",
            "func autoJoin()", "func explain(_ kr:", "static func isFailure(",
            "static func friendly("])
        marks_start = SOURCE.index("static let failureMarks")
        marks = SOURCE[marks_start:SOURCE.index("]", marks_start) + 1]
        self.run_swift(TYPES + r'''
typealias kern_return_t = Int32
let KERN_SUCCESS: Int32 = 0, kIOReturnNotPrivileged: Int32 = 1, kIOReturnNotReady: Int32 = 2
let kIOReturnNotFound: Int32 = 3, kIOReturnUnsupported: Int32 = 4
struct SpeedResult {}
enum SpeedPath { case internet }
enum JoinTarget { case network(String) }
enum LoginItem { static let enabled = false }
enum SavedStore {
    static var writes: [[String: String]] = []
    static func load() -> [String: String] { [:] }
    static func save(_ values: [String: String]) { writes.append(values) }
}
enum Driver {
    enum Sel { case disconnect }
    static var input = WifiStatus()
    static var joins: [String] = []
    static var joinResult: Int32 = KERN_SUCCESS
    static var disconnectResult: Int32 = KERN_SUCCESS
    static func status() -> WifiStatus { input }
    static func join(ssid: String, psk: String) -> Int32 {
        joins.append(ssid)
        if joinResult == KERN_SUCCESS {
            input.joinPending = true
            input.joinSucceeded = false
            input.state = "connecting"
        }
        return joinResult
    }
    static func call(_ selector: Sel) -> Int32 {
        if disconnectResult == KERN_SUCCESS { input.joinPending = false; input.joinSucceeded = false; input.state = "idle" }
        return disconnectResult
    }
}
final class Probe {
''' + fields + "\n" + marks + "\n" + methods + r'''
    func updateOrder(force: Bool) {}
}
func fixture() -> Probe {
    Driver.input = WifiStatus()
    Driver.input.present = true
    Driver.input.state = "idle"
    Driver.input.joinPending = false
    Driver.input.joinSucceeded = false
    Driver.input.events = ["1s auth-fail (old attempt)"]
    Driver.joins = []; Driver.joinResult = KERN_SUCCESS; Driver.disconnectResult = KERN_SUCCESS
    SavedStore.writes = []
    let model = Probe()
    model.refresh()
    return model
}
func finish(_ state: String, _ ssid: String = "", pending: Bool? = false) {
    Driver.input.state = state; Driver.input.ssid = ssid; Driver.input.joinPending = pending
    Driver.input.joinSucceeded = pending == nil ? nil : (pending == false && state == "connected")
}

// A recoverable failure may sit in "failed" while the core backs off for far longer than 45 seconds.
do {
    let model = fixture()
    model.joinTarget = .network("TestAP")
    model.drafts["TestAP"] = "public-test-pass"
    model.join("TestAP", "public-test-pass", remember: true)
    model.pendingSince = Date(timeIntervalSinceNow: -120)
    Driver.input.events.append("3s connect failed: hs-fail (lvl 3)")
    finish("failed", pending: true)
    model.refresh()
    precondition(model.pending?.ssid == "TestAP" && model.busy && model.connectingSSID == "TestAP")
    precondition(model.message == nil && SavedStore.writes.isEmpty)
    // Even an old connected result for the same SSID must not complete a newer queued request.
    finish("connected", "TestAP", pending: true)
    model.refresh()
    precondition(model.pending != nil && SavedStore.writes.isEmpty)
    model.message = "A transient message"
    finish("connected", "TestAP")
    model.refresh()
    precondition(model.pending == nil && !model.busy && model.connectingSSID == nil)
    precondition(model.saved["TestAP"] == "public-test-pass" && SavedStore.writes.count == 1)
    precondition(model.message == nil && model.joinTarget == nil && model.drafts["TestAP"] == nil)
    model.refresh()
    precondition(SavedStore.writes.count == 1, "Refresh must not save twice")
}

// Final rejection ends the spinner immediately and reports the new failure, even with a scan UI pending.
do {
    let model = fixture()
    model.join("TestAP", "public-test-pass", remember: true)
    Driver.input.events.append("4s connect failed: hs-fail")
    model.scanPending = true
    finish("failed")
    model.refresh()
    precondition(model.pending == nil && model.connectingSSID == nil)
    precondition(model.message?.contains("password was not accepted") == true)
    precondition(SavedStore.writes.isEmpty)
}
// A final result without an event still clears pending, and old failures are not reused.
do {
    let model = fixture()
    model.join("TestAP", "public-test-pass", remember: true)
    finish("idle")
    model.refresh()
    precondition(model.pending == nil && model.message?.contains("did not answer") == true)
}
// After giving up the user request the core can already be trying an Info.plist default network.
for state in ["connecting", "scanning"] {
    let model = fixture()
    model.join("TestAP", "public-test-pass", remember: true)
    Driver.input.events.append("4s connect failed: hs-fail")
    finish(state)
    model.refresh()
    precondition(model.pending == nil && model.connectingSSID == nil)
    precondition(model.message?.contains("password was not accepted") == true)
}
// New accepted joins replace old credentials; old completion and events cannot save the old password.
do {
    let model = fixture()
    model.join("FirstAP", "first-test-pass", remember: true)
    Driver.input.events.append("5s connect failed: auth-fail")
    model.join("SecondAP", "second-test-pass", remember: true)
    finish("connected", "FirstAP", pending: true)
    model.refresh()
    precondition(model.pending?.ssid == "SecondAP" && SavedStore.writes.isEmpty)
    finish("connected", "SecondAP")
    model.refresh()
    precondition(model.saved == ["SecondAP": "second-test-pass"] && SavedStore.writes.count == 1)
}
// Refusing a replacement must preserve the accepted request and its credential context.
do {
    let model = fixture()
    model.join("FirstAP", "first-test-pass", remember: true)
    Driver.joinResult = kIOReturnNotReady
    model.join("SecondAP", "second-test-pass", remember: true)
    precondition(model.pending?.ssid == "FirstAP")
    finish("connected", "FirstAP")
    model.refresh()
    precondition(model.saved == ["FirstAP": "first-test-pass"])
}
// Accepted cancellation prevents later status/scan events from saving or automatically joining again.
do {
    let model = fixture()
    model.join("TestAP", "public-test-pass", remember: true)
    model.disconnect()
    precondition(model.pending == nil && model.userOff && model.connectingSSID == nil)
    finish("connected", "TestAP")
    model.refresh()
    precondition(SavedStore.writes.isEmpty)
}
// Failed cancellation leaves the accepted request intact.
do {
    let model = fixture()
    model.join("TestAP", "public-test-pass", remember: true)
    Driver.disconnectResult = kIOReturnNotReady
    model.disconnect()
    precondition(model.pending != nil && !model.userOff)
}
do {
    let model = fixture()
    model.saved["TestAP"] = "previous-test-pass"
    model.join("TestAP", "temporary-test-pass", remember: false)
    finish("connected", "TestAP")
    model.refresh()
    precondition(model.pending == nil && model.saved["TestAP"] == "previous-test-pass")
    precondition(SavedStore.writes.isEmpty)
}
// Old kernels lack the new property: transient failures retain pending until success or the timeout fallback.
do {
    let model = fixture()
    model.join("TestAP", "public-test-pass", remember: true)
    finish("connected", "PreviousAP", pending: nil)
    model.refresh()
    precondition(model.pending != nil && model.connectingSSID == "TestAP")
    finish("failed", pending: nil)
    Driver.input.events.append("6s connect failed: assoc-fail")
    model.refresh()
    precondition(model.pending != nil && model.message == nil)
    finish("connected", "TestAP", pending: nil)
    model.refresh()
    precondition(model.saved["TestAP"] == "public-test-pass")
}
// The App may miss the failed window: an EFI default can reconnect the same SSID with an older password.
do {
    let model = fixture()
    model.saved["TestAP"] = "previous-test-pass"
    model.join("TestAP", "wrong-new-test-pass", remember: true)
    finish("connected", "TestAP")
    Driver.input.joinSucceeded = false
    model.refresh()
    precondition(model.pending == nil && model.connectingSSID == nil)
    precondition(model.saved["TestAP"] == "previous-test-pass" && SavedStore.writes.isEmpty)
    precondition(model.message != nil)
}
// A verified user password remains valid even if the App polls only after the new link has dropped.
do {
    let model = fixture()
    model.join("TestAP", "verified-test-pass", remember: true)
    finish("failed")
    Driver.input.joinSucceeded = true
    model.message = "Connection dropped"
    model.refresh()
    precondition(model.pending == nil && model.saved["TestAP"] == "verified-test-pass")
    precondition(SavedStore.writes.count == 1 && model.message == nil)
    model.refresh()
    precondition(SavedStore.writes.count == 1)
}
// A transitional kext with only the pending flag can still use the connected/SSID compatibility path.
do {
    let model = fixture()
    model.join("TestAP", "public-test-pass", remember: true)
    finish("connected", "TestAP")
    Driver.input.joinSucceeded = nil
    model.refresh()
    precondition(model.saved["TestAP"] == "public-test-pass")
}
do {
    let model = fixture()
    model.join("TestAP", "public-test-pass", remember: true)
    model.pendingSince = Date(timeIntervalSinceNow: -46)
    finish("connecting", pending: nil)
    model.refresh()
    precondition(model.pending != nil, "Legacy timeout must not interrupt a busy state")
    finish("failed", pending: nil)
    model.refresh()
    precondition(model.pending == nil && model.message?.contains("did not answer") == true)
}
// Both a locally tracked request and an in-flight request observed from the kext block auto-join.
do {
    let model = fixture()
    model.saved["SavedAP"] = "saved-test-pass"
    Driver.input.nets = [WifiNet(ssid: "SavedAP", channel: 48, rssi: -45, security: "wpa2")]
    model.join("ManualAP", "manual-test-pass", remember: true)
    finish("failed", pending: true)
    Driver.input.scanGen += 1
    model.refresh(); model.autoJoin()
    precondition(Driver.joins == ["ManualAP"])
    model.pending = nil
    model.autoJoin()
    precondition(Driver.joins == ["ManualAP"], "Do not hijack a driver request with no local pending tuple")
    finish("idle")
    model.refresh(); model.autoJoin()
    precondition(Driver.joins == ["ManualAP", "SavedAP"])
}
''')

    def test_login_disable_persists_without_bootout(self):
        method = block("static func set(_ on: Bool)")
        self.run_swift(r'''
enum LoginItem {
    static let label = "synthetic.itlmt7922.test"
    static let plist = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        .appendingPathComponent("isolated-login-item/test.plist")
    static var calls: [[String]] = []
    static func launchctl(_ args: [String]) {
        precondition(FileManager.default.fileExists(atPath: plist.path), "Persist before registering a service")
        let data = NSDictionary(contentsOf: plist)
        precondition(data?["Label"] as? String == label)
        calls.append(args)
    }
''' + method + r'''
}
LoginItem.set(true)
precondition(FileManager.default.fileExists(atPath: LoginItem.plist.path))
precondition(LoginItem.calls.map { $0[0] } == ["bootstrap"])
LoginItem.calls = []
LoginItem.set(false)
precondition(!FileManager.default.fileExists(atPath: LoginItem.plist.path))
precondition(LoginItem.calls.isEmpty, "Disabling must preserve the current App rather than boot it out")
LoginItem.set(false)
precondition(LoginItem.calls.isEmpty, "Disabling an absent login item must be harmless")
// The LaunchAgent may still own this process after disabling: re-enabling must not boot this App out.
LoginItem.set(true)
precondition(FileManager.default.fileExists(atPath: LoginItem.plist.path))
precondition(LoginItem.calls.map { $0[0] } == ["bootstrap"], "Re-enabling must keep the loaded instance alive")
''')

    def test_launchctl_waits_only_after_successful_launch(self):
        method = block("private static func launchctl(_ args:")
        self.run_swift(r'''
enum LaunchError: Error { case failed }
final class Process {
    static var shouldFail = false
    static var runs = 0, waits = 0
    var executableURL: URL?, arguments: [String]?
    var standardOutput: Any?, standardError: Any?
    func run() throws {
        Self.runs += 1
        if Self.shouldFail { throw LaunchError.failed }
    }
    func waitUntilExit() { Self.waits += 1 }
}
enum LoginItem {
''' + method + r'''
    static func test() { launchctl(["synthetic"]) }
}
Process.shouldFail = true
LoginItem.test()
precondition(Process.runs == 1 && Process.waits == 0)
Process.shouldFail = false
LoginItem.test()
precondition(Process.runs == 2 && Process.waits == 1)
''')


if __name__ == "__main__":
    unittest.main()
