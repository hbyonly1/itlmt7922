// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (c) 2026 thanhnndev and contributors
// Portions derived from the Linux mt76 driver, Copyright (C) 2020, 2023 MediaTek Inc. (BSD-3-Clause-Clear)
// itlmt7922 - PCI probe: map BAR0, take driver ownership from the firmware, read the chip id, then, by default,
// start the firmware / scan / connect worker implemented in itlmt7922_m1.cpp, _m2.cpp and _m3.cpp.
#include "itlmt7922.hpp"
#include "mt7922_regs.h"

#include <string.h>
#include <pexpert/pexpert.h>

// IOCreateThread() is deprecated: a detached kernel thread through the KPI does the same.
static bool startThread(void (*fn)(void *), void *arg)
{
    thread_t th = nullptr;
    if (kernel_thread_start((thread_continue_t)fn,arg,&th)!=KERN_SUCCESS) return false;
    thread_deallocate(th);
    return true;
}

#define super IOService
OSDefineMetaClassAndStructors(itlmt7922, IOService)

uint32_t itlmt7922::rd(uint32_t off)
{
    if (!regs || off>barSize || barSize-off<4 || (off&3)) return 0xffffffffu;
    return *(volatile uint32_t *)(regs+off);
}

void itlmt7922::wr(uint32_t off,uint32_t value)
{
    if (!regs || off>barSize || barSize-off<4 || (off&3)) return;
    *(volatile uint32_t *)(regs+off)=value;
}

// M0 delegates to the full Connac2 map from mt7921/pci.c (__mt7921_reg_addr).
uint32_t itlmt7922::rdMapped(uint32_t addr)
{
    return rdA(addr);
}



// Append a short message to the log buffer, print it, and mirror it to NVRAM variable
// 7C436110-AB2A-4BBB-A880-FE41995C9F82:itlmt7922-log (no keyboard/terminal needed to read it).
void itlmt7922::note(const char *fmt, uint32_t a, uint32_t b, uint32_t c)
{
    char tmp[80];
    snprintf(tmp, sizeof(tmp), fmt, a, b, c);
    IOLog("itlmt7922: %s\n", tmp);
    size_t n = strlen(tmp);
    if (loglen + n + 2 < sizeof(logbuf)) {
        memcpy(logbuf + loglen, tmp, n);
        loglen += n;
        logbuf[loglen++] = ';';
        logbuf[loglen] = 0;
    }
    setProperty("m0-log", logbuf);   // visible to ItlDiag / ioreg
    nvramLog(logbuf);
}

// Same recipe as ItlDiag: the value must be OSData, and the sync has to be forced or it never reaches the firmware variable store
// (string properties were silently dropped: itlmt7922-log never showed up in Windows).
// NVRAM logging is for bring-up without a working macOS (read from Windows/Linux after a hang). Each write forces a flash
// update through the firmware, so it is off unless the boot-arg mt7922_nvlog=1 is set; the same text is always in the registry
// (ioreg -rc itlmt7922: m0-log .. m3-log, stat-log, ba-log).
static int gNvlog = -1;
static bool nvlogOn()
{
    if (gNvlog < 0) { uint32_t v = 0; gNvlog = (PE_parse_boot_argn("mt7922_nvlog", &v, sizeof(v)) && v) ? 1 : 0; }
    return gNvlog == 1;
}
static void nvramSet(IORegistryEntry *opt, const char *name, const char *s, size_t n)
{
    if (!nvlogOn()) return;
    OSData *d = OSData::withBytes(s, (unsigned)n);
    if (d) { opt->setProperty(name, d); d->release(); }
    opt->setProperty("IONVRAM-FORCESYNCNOW-PROPERTY", name);
}

void itlmt7922::nvramLog(const char *msg)
{
    IORegistryEntry *opt = IORegistryEntry::fromPath("/options", gIODTPlane);
    if (!opt) { IOLog("itlmt7922: no /options node\n"); return; }
    nvramSet(opt, "itlmt7922-log", msg, strlen(msg));
    opt->release();
}

// Whole m3 log in 380 byte pieces (itlk0..itlk4), written only when a piece changed. Lets the log reach Windows even when
// ItlDiag is disabled (it is the thing under suspicion for the input lag).
void itlmt7922::nvramChunks(const char *buf)
{
    static char last[8][384];
    IORegistryEntry *opt = IORegistryEntry::fromPath("/options", gIODTPlane);
    if (!opt) return;
    size_t len = strlen(buf);
    for (int c = 0; c < 8 && (size_t)c * 380 < len; c++) {
        char piece[384], name[8];
        size_t from = (size_t)c * 380, n = len - from > 380 ? 380 : len - from;
        memcpy(piece, buf + from, n);
        piece[n] = 0;
        if (strcmp(piece, last[c]) == 0) continue;
        strlcpy(last[c], piece, sizeof(last[c]));
        snprintf(name, sizeof(name), "itlk%d", c);
        nvramSet(opt, name, piece, n);
    }
    opt->release();
}

// Block Ack / fast-mode log (itlb0..itlb2), 380 characters per variable. Separate from itlk* because that log is full by link-up.
void itlmt7922::nvramBa(const char *buf)
{
    static char last[3][384];
    IORegistryEntry *opt = IORegistryEntry::fromPath("/options", gIODTPlane);
    if (!opt) return;
    size_t len = strlen(buf);
    for (int c = 0; c < 3 && (size_t)c * 380 < len; c++) {
        char piece[384], name[8];
        size_t from = (size_t)c * 380, n = len - from > 380 ? 380 : len - from;
        memcpy(piece, buf + from, n);
        piece[n] = 0;
        if (strcmp(piece, last[c]) == 0) continue;
        strlcpy(last[c], piece, sizeof(last[c]));
        snprintf(name, sizeof(name), "itlb%d", c);
        nvramSet(opt, name, piece, n);
    }
    opt->release();
}

// Rolling one-line status of the data path (itls0), overwritten each time.
void itlmt7922::nvramStat(const char *msg)
{
    setProperty("stat-log", msg);    // ItlDiag mirrors it into ITLLOG.BIN; the NVRAM variable below does not always land
    IORegistryEntry *opt = IORegistryEntry::fromPath("/options", gIODTPlane);
    if (!opt) return;
    nvramSet(opt, "itls0", msg, strlen(msg));
    opt->release();
}

void itlmt7922::dumpState()
{
    uint32_t chip = rdMapped(MT_HW_CHIPID);
    uint32_t rev  = rdMapped(MT_HW_REV);
    uint32_t lp   = rd(0x0e0000u + (MT_CONN_ON_LPCTL - 0x7c060000u));
    note("CHIP=%08x REV=%08x LP=%08x", chip, rev, lp);
    IOLog("itlmt7922: ASIC revision: %04x%02x (expect 7922xx)\n", chip & 0xffff, rev & 0xff);
}

// Debug aid: with boot-arg mt7922_hold=<seconds> repeat the log on the verbose console so it can be photographed.
void itlmt7922::holdLog()
{
    uint32_t hold = 0;
    if (PE_parse_boot_argn("mt7922_hold", &hold, sizeof(hold)) && hold) {
        for (uint32_t t = 0; t < hold && !shouldStop(); t += 3) {
            IOLog("itlmt7922: [t=%us] %s\n", t, logbuf);
            IOSleep(3000);
        }
    }
}

bool itlmt7922::start(IOService *provider)
{
    if (!super::start(provider)) return false;
    uint32_t stage = 3;
    uint32_t chip = 0;
    bool fwOwned = false;
    bool runM1 = false;
    workerLock = IOLockAlloc();
    txLock = IOLockAlloc();
    cmdLock = IOLockAlloc();
    nativeLock = IOLockAlloc();
    if (!workerLock || !txLock || !cmdLock || !nativeLock) return false;
    uint32_t nativeDP = 0;
    nativeMode = PE_parse_boot_argn("mt7922_native_dp", &nativeDP, sizeof(nativeDP)) && nativeDP;
    setProperty("port-version","0.2.2-full-experimental");
    setProperty("wifi-state", "off");                         // until stage 3 establishes a link
    setProperty("wifi-join-succeeded", kOSBooleanFalse);
    setProperty("wifi-join-pending", kOSBooleanFalse);

    pci = OSDynamicCast(IOPCIDevice, provider);
    if (!pci) { IOLog("itlmt7922: provider is not IOPCIDevice\n"); return false; }
    pci->retain();
    if (!pci->open(this)) { IOLog("itlmt7922: open failed\n"); pci->release(); pci = nullptr; return false; }

    uint16_t vid = pci->configRead16(kIOPCIConfigVendorID);
    uint16_t did = pci->configRead16(kIOPCIConfigDeviceID);
    uint16_t cmd = pci->configRead16(kIOPCIConfigCommand);
    note("start %04x:%04x cmd=%04x",vid,did,cmd);
    if (vid!=0x14c3 || (did!=0x0616 && did!=0x7922)) goto fail;
    if (PE_parse_boot_argn("mt7922_stage",&stage,sizeof(stage))) diagnosticStage=stage<=3?stage:0;
    setProperty("diagnostic-stage",diagnosticStage,32);

    pci->setMemoryEnable(true);
    pci->setBusMasterEnable(false);   // M0 does no DMA

    bar0 = pci->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
    if (!bar0) { IOLog("itlmt7922: BAR0 map failed\n"); goto fail; }
    regs = (volatile uint8_t *)bar0->getVirtualAddress();
    if (!regs || bar0->getLength()>0xffffffffULL) goto fail;
    barSize = (uint32_t)bar0->getLength();
    note("bar0 size=%x", barSize);
    if (barSize < MT_BAR0_DIRECT_LIMIT) { IOLog("itlmt7922: BAR0 too small\n"); goto fail; }

    note("lp0=%08x",rdA(MT_CONN_ON_LPCTL));
    for (int retry=0;retry<10 && !shouldStop();retry++) {
        wrA(MT_CONN_ON_LPCTL,PCIE_LPCR_HOST_SET_OWN);
        if (pollA(MT_CONN_ON_LPCTL,PCIE_LPCR_HOST_OWN_SYNC,PCIE_LPCR_HOST_OWN_SYNC,50)) { fwOwned=true; break; }
    }
    if (!fwOwned || !driverOwn()) { note("own FAIL"); goto fail; }
    note("own OK");
    chip=rdA(MT_HW_CHIPID);
    dumpState();
    if ((chip&0xffff)!=0x7922) { note("unsupported ASIC"); goto fail; }

    holdLog();

    // Stage 3 is the default; mt7922_stage=0/1/2 selects an earlier checkpoint.
    runM1=diagnosticStage>0 && !m1Started;
    // Native mode: the Wi-Fi interface takes its station address from this service when it matches, and the address the radio
    // uses on air is the firmware's, read by M2. Publishing the service before that would give the interface a different
    // address from the one in the 802.11 headers (DHCP / ARP replies are then addressed to a station the AP never heard of).
    // The worker publishes (publishService) as soon as the address is known, or when M1 / M2 gave up.
    if (nativeMode && runM1) regPending = true;
    else registerService();
    if (runM1) {
        m1Started=true;
        workerRunning=true;
        retain();
        if (!startThread(m1Thread,this)) {
            workerRunning=false;
            release();
            setProperty("wifi-state","worker-failed");
            publishService();
        }
    }
    return true;

fail:
    holdLog();
    stop(provider);
    return false;
}

// Once only, from the worker thread (or from start() when no worker runs).
void itlmt7922::publishService()
{
    if (__atomic_exchange_n(&regPending, false, __ATOMIC_ACQ_REL)) {
        note(getProperty("itlmt_mac_source") ? "registerService (native: address known)" : "registerService (native: address not read)");
        registerService();
    }
}

void itlmt7922::stop(IOService *provider)
{
    __atomic_store_n(&stopping,true,__ATOMIC_RELEASE);
    m3linkUp=false;
    if (workerLock) {
        IOLockLock(workerLock);
        while (workerRunning) IOLockSleep(workerLock,&workerRunning,THREAD_UNINT);
        IOLockUnlock(workerLock);
    }
    quiesceHardware();
    regs=nullptr;
    if (bar0) { bar0->release(); bar0=nullptr; }
    if (pci) { pci->close(this); pci->release(); pci=nullptr; }
    super::stop(provider);
}

void itlmt7922::free()
{
    if (workerLock) { IOLockFree(workerLock); workerLock=nullptr; }
    if (txLock) { IOLockFree(txLock); txLock=nullptr; }
    if (cmdLock) { IOLockFree(cmdLock); cmdLock=nullptr; }
    if (nativeLock) { IOLockFree(nativeLock); nativeLock=nullptr; }
    super::free();
}

bool itlmt7922::quiesceHardware()
{
    m3linkUp=false; m3dataOn=false; m3wantEapol=false;
    if (txLock) IOLockLock(txLock);
    bool stopped=true;
    if (busMasterOn && pci && regs) {
        dmaDisable();
        pci->setBusMasterEnable(false);
        uint16_t command=pci->configRead16(kIOPCIConfigCommand);
        if (command!=0xffff && (command&4)) {
            m1log("bus mastering still on cmd=%04x; keeping DMA buffers",command);
            stopped=false;
        } else busMasterOn=false;
    }
    if (stopped) {
        txPool=false;
        ringFree(txWm); ringFree(txFwdl); ringFree(rxEvt); ringFree(rxWa); ringFree(rxData); ringFree(txData);
        txClrAll();
    }
    if (txLock) IOLockUnlock(txLock);
    return stopped;
}
