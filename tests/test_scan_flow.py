#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause-Clear
"""Exercise the actual scan coordinator with injected firmware pass outcomes.

No IOKit or radio is used. The function under test is extracted from the driver
source so these cases cover its real control flow rather than a duplicate.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def scan_function():
    source = (ROOT / 'src/itlmt7922_m2.cpp').read_text()
    start = source.index('int itlmt7922::m2Scan(const char *ssid)')
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


HARNESS = r'''
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

class itlmt7922 {
public:
    int result[2] = {0, 0};
    int stopAfter = -1, faultAfter = -1;
    bool stopping = false, firmwareFault = false;
    std::vector<int> passes;
    std::vector<std::string> requests;
    std::vector<std::string> logs;
    int m2Scan(const char *ssid);
    bool shouldStop() const { return stopping; }
    int m2ScanPass(const char *ssid, int part) {
        assert(part == 0 || part == 1);
        passes.push_back(part);
        requests.emplace_back(ssid ? ssid : "");
        if (part == stopAfter) stopping = true;
        if (part == faultAfter) firmwareFault = true;
        return result[part];
    }
    void m2log(const char *format, ...) {
        char buffer[256];
        va_list args; va_start(args, format);
        std::vsnprintf(buffer, sizeof(buffer), format, args); va_end(args);
        logs.emplace_back(buffer);
    }
};

%FUNCTION%

int main(int argc, char **argv) {
    assert(argc == 2);
    const std::string test = argv[1];
    itlmt7922 driver;
    if (test == "primary-timeout") {
        driver.result[0] = -110;
        assert(driver.m2Scan(nullptr) == -110);
        assert(driver.passes == std::vector<int>({0}));
    } else if (test == "primary-rejected") {
        driver.result[0] = 65539;
        assert(driver.m2Scan(nullptr) == 65539);
        assert(driver.passes == std::vector<int>({0}));
    } else if (test == "dfs-success") {
        assert(driver.m2Scan(nullptr) == 0);
        assert(driver.passes == std::vector<int>({0, 1}));
        assert(driver.logs.empty());
    } else if (test == "dfs-timeout" || test == "dfs-rejected") {
        driver.result[1] = test == "dfs-timeout" ? -110 : 65539;
        assert(driver.m2Scan(nullptr) == 0);
        assert(driver.passes == std::vector<int>({0, 1}));
        assert(!driver.logs.empty());
    } else if (test == "directed") {
        assert(driver.m2Scan("SyntheticAP") == 0);
        assert(driver.passes == std::vector<int>({0}));
        assert(driver.requests == std::vector<std::string>({"SyntheticAP"}));
    } else if (test == "stop-after-primary") {
        driver.stopAfter = 0;
        assert(driver.m2Scan(nullptr) == -125);
        assert(driver.passes == std::vector<int>({0}));
    } else if (test == "fault-after-primary") {
        driver.faultAfter = 0;
        assert(driver.m2Scan(nullptr) == -5);
        assert(driver.passes == std::vector<int>({0}));
    } else if (test == "stop-during-dfs") {
        driver.stopAfter = 1; driver.result[1] = -125;
        assert(driver.m2Scan(nullptr) == -125);
        assert(driver.passes == std::vector<int>({0, 1}));
    } else if (test == "fault-during-dfs") {
        driver.faultAfter = 1; driver.result[1] = -5;
        assert(driver.m2Scan(nullptr) == -5);
        assert(driver.passes == std::vector<int>({0, 1}));
    } else {
        assert(false && "unknown test case");
    }
}
'''


class ScanFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='mt7922-scan-flow-')
        cls.addClassCleanup(cls.directory.cleanup)
        directory = Path(cls.directory.name)
        source = directory / 'scan_flow.cpp'
        source.write_text(HARNESS.replace('%FUNCTION%', scan_function()))
        cls.binary = directory / 'scan_flow'
        compiler = shlex.split(os.environ.get('CXX', 'c++'))
        subprocess.run(compiler + [
            '-std=c++11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
            str(source), '-o', str(cls.binary),
        ], check=True)

    def run_case(self, case):
        subprocess.run([str(self.binary), case], check=True)

    def test_primary_failures_do_not_start_dfs(self):
        for case in ('primary-timeout', 'primary-rejected'):
            with self.subTest(case=case):
                self.run_case(case)

    def test_optional_dfs_outcomes_preserve_primary_success(self):
        for case in ('dfs-success', 'dfs-timeout', 'dfs-rejected'):
            with self.subTest(case=case):
                self.run_case(case)

    def test_directed_scan_stays_on_primary_pass(self):
        self.run_case('directed')

    def test_stop_and_firmware_fault_remain_fatal(self):
        for case in ('stop-after-primary', 'fault-after-primary',
                     'stop-during-dfs', 'fault-during-dfs'):
            with self.subTest(case=case):
                self.run_case(case)


if __name__ == '__main__':
    unittest.main()
