// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (c) 2026 thanhnndev and contributors
// Portions derived from the Linux mt76 driver, Copyright (C) 2020, 2023 MediaTek Inc. (BSD-3-Clause-Clear)
// itlmt7922 - M3: join the configured WPA2-PSK network and expose an Ethernet interface.
// Enabled with boot-arg itlmt_m3=1 (implies itlmt_m2=1; the target AP is picked from the M2 scan).
// Credentials come from the kext Info.plist personality keys itl_ssid / itl_psk (filled in locally by scripts/inject-creds.ps1,
// never committed). Progress is logged with m3log() into "m3-log" (mirrored to NVRAM itln0..itln3 by ItlDiag) and a one-line
// summary in "m3-res" (itln4).
// Connac2 firmware ABI port of Linux mt76 mt7921 (the upstream MT7922 path).
#include "itlmt7922.hpp"
#include "mt7922_regs.h"
#include "itl_wpa.h"
#include "../codec/mt7922_data_codec.h"

#include <string.h>
#include <stdarg.h>
#include <libkern/libkern.h>
#include <sys/random.h>
#include <kern/clock.h>
#include <mach/mach_time.h>

#define ITL_TIMEOUT -110
#define ITL_EIO     -5
#define ITL_EINVAL  -22

void itlmt7922::m3log(const char *fmt, ...)
{
    char tmp[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    IOLog("itlmt7922: M3 %s\n", tmp);
    size_t n = strlen(tmp);
    if (n + 2 < sizeof(m3buf)) {
        // Ring, not a one-shot buffer: appending only while there is room meant that after ~3 KB the log went silent, exactly
        // when a repeated failure needed it. Drop the oldest ';'-separated entries instead.
        while (m3len + n + 2 >= sizeof(m3buf)) {
            char *sep = (char *)memchr(m3buf, ';', m3len);
            size_t cut = sep ? (size_t)(sep - m3buf) + 1 : m3len;
            memmove(m3buf, m3buf + cut, m3len - cut);
            m3len -= cut;
            m3buf[m3len] = 0;
        }
        memcpy(m3buf + m3len, tmp, n);
        m3len += n;
        m3buf[m3len++] = ';';
        m3buf[m3len] = 0;
    }
    setProperty("m3-log", m3buf);
    nvramLog(tmp);                            // last step survives a hang or reboot (variable itlmt7922-log)
    nvramChunks(m3buf);                       // and the whole log (itlk0..itlk4)
}

void itlmt7922::m3Publish(const char *stage)
{
    snprintf(m3res, sizeof(m3res), "%s tgt=%d ch=%u bssid=%02x%02x%02x ie=%u", stage, tgtFound ? 1 : 0, tgtCh, tgtBssid[3],
             tgtBssid[4], tgtBssid[5], tgtIeLen);
    setProperty("m3-res", m3res);
    size_t sl = strlen(stage);
    if ((sl >= 4 && !strcmp(stage + sl - 4, "fail")) || !strcmp(stage, "nocred")) evLog("connect failed: %s (lvl %u)", stage, lvl);
}

// Called by rxParseFrame for every beacon / probe response. `frame` points at the 802.11 header.
void itlmt7922::m3Capture(const uint8_t *frame, uint32_t len, const char *ssid, uint8_t ch)
{
    if (!m3On || !m3ssid[0] || len < 36 || strcmp(ssid, m3ssid) != 0) return;
    // prefer 5 GHz; otherwise keep the first one seen
    if (tgtFound && !(ch > 14 && tgtCh <= 14)) return;
    tgtFound = true;
    memcpy(tgtBssid, frame + 16, 6);
    tgtCh = ch;
    tgtBcnInt = (uint16_t)(frame[32] | (frame[33] << 8));
    tgtCap = (uint16_t)(frame[34] | (frame[35] << 8));
    tgtIeLen = len - 36 > sizeof(tgtIe) ? (uint32_t)sizeof(tgtIe) : len - 36;
    memcpy(tgtIe, frame + 36, tgtIeLen);
}

// The passive wildcard scan already stores each beacon in aps[]; reuse that instead of sending a directed (active) probe.
// Active probing is not allowed on DFS channels, so a 5 GHz AP on one of them could be listed by the scan and still never
// be joined through m2Scan(m3ssid). Prefer a 5 GHz BSS over a 2.4 GHz one, as m3Capture does.
bool itlmt7922::m3UseCached(const char *ssid, uint32_t maxAgeMs)
{
    const uint32_t now = nowMs();
    int best = -1;
    for (int i = 0; i < nAps; i++) {
        const itl_ap &a = aps[i];
        if (!a.ssid[0] || !a.ieLen || strcmp(a.ssid, ssid) != 0) continue;
        if ((uint32_t)(now - a.seenMs) > maxAgeMs) continue;
        if (best < 0) { best = i; continue; }
        const itl_ap &b = aps[best];
        const bool a5 = a.ch > 14, b5 = b.ch > 14;
        if (a5 != b5) { if (a5) best = i; continue; }
        if (a.rssi > b.rssi) best = i;
    }
    if (best < 0) return false;
    const itl_ap &a = aps[best];
    tgtFound = true;
    memcpy(tgtBssid, a.bssid, 6);
    tgtCh = a.ch;
    tgtCap = a.cap;
    tgtBcnInt = a.bcnInt;
    tgtIeLen = a.ieLen > (uint16_t)sizeof(tgtIe) ? (uint32_t)sizeof(tgtIe) : a.ieLen;
    memcpy(tgtIe, a.ie, tgtIeLen);
    tgtRssi = a.rssi;
    tgtLastBcnMs = a.seenMs ? a.seenMs : 1;
    return true;
}

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------
static inline uint32_t le32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static inline void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static inline void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }

#define M3_BSS_IDX     0
#define M3_BMC_WCID    19                   // MT792x_WTBL_RESERVED - bss idx
#define M3_AP_WCID     1

#define UNI_STA_REC_UPDATE   0x03
#define UNI_ROC              0x27
#define UNI_BSS_INFO_UPDATE  0x02

// MCU message under construction: a fixed header (4 bytes BSS_INFO, 8 bytes STA_REC; tlv_num is at offset 2 in both)
// followed by TLVs.
struct M3Msg {
    uint8_t b[640];
    uint16_t n;
    void init(uint16_t hdr) { bzero(b, sizeof(b)); n = hdr; }
    uint8_t *tlv(uint16_t tag, uint16_t len)
    {
        uint8_t *p = b + n;
        put16(p, tag); put16(p + 2, len);
        n += len;
        uint16_t c = (uint16_t)(b[2] | (b[3] << 8)) + 1;
        b[2] = (uint8_t)c; b[3] = (uint8_t)(c >> 8);
        return p;
    }
};

// Sends a UNI command and logs the firmware's status word (event payload: cid, pad[3], status le32 at event offset 48).
int itlmt7922::m3Cmd(uint8_t cid, const void *payload, size_t plen, const char *name)
{
    if (shouldStop() || firmwareFault) return ITL_EIO;
    uint8_t ev[512] = {};
    uint32_t evl = 0;
    int rc = uniSend(cid, payload, plen, false, ev, sizeof(ev), &evl, 3000);
    int status = evl >= 44 ? (int)le32(ev + 40) : -1;
    if (!rc && (evl < 44 || ev[28] != 1 || ev[36] != cid || status)) rc = ITL_EIO;
    m3log("%s rc=%d st=%d", name, rc, status);
    return rc;
}

// Everything that arrives on the MCU event ring: frames go to the beacon parser, events to m3Event.
int itlmt7922::m3PumpOnce()
{
    if (shouldStop() || firmwareFault) return 0;
    uint32_t before = rxPkts + evCount;
    rxDataPoll();
    ethFlush();
    return (rxPkts + evCount) != before;
}

void itlmt7922::m3Pump(uint32_t ms)
{
    for (uint32_t i = 0; i < ms && !shouldStop() && !firmwareFault; i++) {
        m3PumpOnce();
        if (m3sleepy) IOSleep(1); else IODelay(1000);
    }
}

// Unsolicited firmware events we care about.
void itlmt7922::m3Event(const uint8_t *ev, uint32_t len)
{
    if (len >= 8 && (le32(ev) >> 27) == 6) { m3TxFree(ev, len); return; }
    if (len < 36) return;
    const uint8_t eid = ev[28];
    const bool uni = (ev[30] & 4) != 0;
    if ((!uni && eid == 0xf0) || (uni && eid == 0x0a)) {
        firmwareFault = true; m3lost = true; recoverWanted = true;
        strlcpy(m3lostWhy, "firmware coredump", sizeof(m3lostWhy));
        m3log("firmware coredump namespace=%s eid=%02x", uni ? "UNI" : "legacy", eid);
        return;
    }
    // Legacy debug event has id/type/flag/value/len followed by content.
    if (!uni && eid == 0x27 && len >= 46 && ev[38] == 3 && m3fwLogged < 24) {
        m3fwLogged++;
        uint16_t length = (uint16_t)(ev[44] | (ev[45] << 8));
        if (length > len - 46) length = (uint16_t)(len - 46);
        char text[96]; uint32_t n = length < sizeof(text)-1 ? length : sizeof(text)-1;
        for (uint32_t i=0;i<n;i++) text[i] = ev[46+i]>=32 && ev[46+i]<127 ? (char)ev[46+i] : '.';
        text[n]=0; m3log("fw: %s", text);
    }
    if (!m3On || m3linkUp || len < 47) return;
    if (uni && eid == UNI_ROC) {
        // Connac2 rxd36 + event hdr4 + TLV4 -> grant data44.
        uint16_t tag = (uint16_t)(ev[40] | (ev[41] << 8));
        uint16_t tl = (uint16_t)(ev[42] | (ev[43] << 8));
        if (tag != 0 || tl < 20 || len < 40u + tl || ev[44] != M3_BSS_IDX || ev[45] != rocTok) return;
        rocStatus = ev[46]; rocGrant = true;
        m3log("roc grant bss=%u tok=%u status=%u", ev[44], ev[45], ev[46]);
    }
}

// Rates / RSN of the target AP from the captured beacon IEs.
void itlmt7922::m3ParseAp()
{
    static const uint8_t r5g[8] = {12, 18, 24, 36, 48, 72, 96, 108};    // 500 kb/s units
    static const uint8_t rcck[4] = {2, 4, 11, 22};
    const uint8_t *ie = tgtIe, *end = tgtIe + tgtIeLen;
    apSupp = apBasic = apCck = apBasicCck = 0;
    apRsnLen = 0;
    while (ie + 2 <= end && ie + 2 + ie[1] <= end) {
        uint8_t id = ie[0], l = ie[1];
        if (id == 1 || id == 50) {
            for (int i = 0; i < l; i++)
                for (int k = 0; k < 8; k++)
                    if ((ie[2 + i] & 0x7f) == r5g[k]) { apSupp |= 1u << k; if (ie[2 + i] & 0x80) apBasic |= 1u << k; }
            for (int i = 0; i < l; i++)
                for (int k = 0; k < 4; k++)
                    if ((ie[2 + i] & 0x7f) == rcck[k]) { apCck |= 1u << k; if (ie[2 + i] & 0x80) apBasicCck |= 1u << k; }
        } else if (id == 48 && l <= sizeof(apRsn) - 2) {
            apRsnLen = (uint8_t)(l + 2);
            memcpy(apRsn, ie, apRsnLen);
        }
        ie += 2 + l;
    }
    m3log("ap rates supp=%02x basic=%02x cck=%x/%x rsn=%u", apSupp, apBasic, apCck, apBasicCck, apRsnLen);
    m3FastPlan();
    if (apRsnLen >= 14) {
        // version(2) group(4) pairwise count(2) ...
        const uint8_t *r = apRsn + 2;
        uint16_t pc = (uint16_t)(r[6] | (r[7] << 8));
        m3log("rsn group=%02x pairwise n=%u first=%02x akm1=%02x", r[5], pc, pc ? r[11] : 0,
              (apRsnLen >= 12 + 4 * pc + 6) ? r[8 + 4 * pc + 2 + 3] : 0);
    }
}

// Features at `level` for the current AP: bit 0 A-MSDU, bit 1 HE, bit 2 160 MHz channel. Used to skip levels that change nothing.
uint8_t itlmt7922::fastSig(uint8_t level)
{
    bool g2 = tgtCh <= 14;
    uint8_t bw, center;
    itl_caps_channel(&apCaps, tgtCh, level >= 5 && !g2 && !no160, &bw, &center);
    return (level >= 4 && !noAmsdu ? 1 : 0) | ((level >= 6 && apCaps.he) ? 2 : 0) | (bw == 3 ? 4 : 0);
}

// HT/VHT/HE plan (boot-arg mt7922_fast=<level>): what the AP offers, the channel width to run at and the rate to report to macOS.
// Stays off (legacy 6 Mb/s path, exactly as before) unless the AP advertises HT. 2.4 GHz is HT / HE only (no VHT).
void itlmt7922::m3FastPlan()
{
    fastActive = false;
    txPool = true;
    fastHe = fastAmsdu = fastAllow160 = false;
    if (lvl > 5) lvl = 5;
    if (!m3fast || lvl < 1) return;
    itl_caps_parse(tgtIe, tgtIeLen, &apCaps);
    bool g2 = tgtCh <= 14;
    if (g2) { apCaps.vht = false; apCaps.vhtOp = false; }
    if (!apCaps.ht) {
        m3log("fast: off (ch=%u ht=%d)", tgtCh, apCaps.ht ? 1 : 0);
        baLog("fast off ch=%u ht=%d", tgtCh, apCaps.ht ? 1 : 0);
        return;
    }
    itl_caps_channel(&apCaps, tgtCh, lvl >= 5 && !g2 && !no160, &fastBw, &fastCenter);
    fastAllow160 = fastBw == 3;
    fastAmsdu = lvl >= 4 && !noAmsdu;
    fastHe = false; // HE ABI is not enabled in the first Connac2 full port.
    fastNss = itl_caps_nss(&apCaps);
    fastRate = itl_caps_max_rate(&apCaps, fastBw, fastHe);
    fastActive = true;
    txPool = true;
    // Token ownership is retained until TXFREE or a quiesced hardware reset.
    m3log("fast: on lvl=%u ht=%d vht=%d he=%d/%d bw=%u center=%u nss=%u rate~%u htcap=%04x vhtcap=%08x", lvl, apCaps.ht ? 1 : 0,
          apCaps.vht ? 1 : 0, apCaps.he ? 1 : 0, fastHe ? 1 : 0, fastBw, fastCenter, fastNss, fastRate, apCaps.htCap, apCaps.vhtCap);
    baLog("fast on lvl=%u ch=%u bw=%u c=%u nss=%u ht=%04x vht=%08x ampdu=%02x vhtop=%u/%u/%u", lvl, tgtCh, fastBw, fastCenter, fastNss,
          apCaps.htCap, apCaps.vhtCap, apCaps.ampduParm, apCaps.vhtOpWidth, apCaps.vhtSeg0, apCaps.vhtSeg1);
    baLog("fast feat amsdu=%d he=%d(ap %d) 160=%d heph=%02x%02x%02x%02x hemac=%02x%02x%02x%02x map=%04x/%04x", fastAmsdu ? 1 : 0,
          fastHe ? 1 : 0, apCaps.he ? 1 : 0, fastAllow160 ? 1 : 0, apCaps.hePhy[0], apCaps.hePhy[1], apCaps.hePhy[2], apCaps.hePhy[3],
          apCaps.heMac[0], apCaps.heMac[1], apCaps.heMac[2], apCaps.heMac[3], apCaps.heRx80, apCaps.heRx160);
}

// ---------------------------------------------------------------------------------------------
// hardware / firmware prep (mt7922_mac_init, mt7922_mcu_set_channel_domain)
// ---------------------------------------------------------------------------------------------
#define MT_MDP_DCR0              0x820cd000
#define MT_MDP_DCR0_DAMSDU_EN    (1u << 15)
#define MT_MDP_DCR1              0x820cd004
#define MT_WTBL_UPDATE_REG       0x820d4230

int itlmt7922::m3HwPrep()
{
    if (shouldStop() || firmwareFault) return ITL_EIO;
    constexpr uint32_t CE=1u<<18;
    if (!m3hw) {
        int result=0;
        const uint8_t efuse[4]={0,1,0,0};
        int rc=mcuSend(0x21ed,efuse,sizeof(efuse),true,&result);
        if (rc) return rc;
        rmwA(MT_MDP_DCR1,0xfff8u,1536u<<3);
        rmwA(MT_MDP_DCR0,1u<<19,1u<<15); // raw 802.11, hardware deaggregation
        for (unsigned band=0;band<2;band++) {
            uint32_t dma=band?0x820f7000u:0x820e7000u;
            uint32_t rcpi=band?0x820f9008u:0x820e9008u;
            rmwA(dma,0xfff8u | (1u<<23),1536u<<3);
            rmwA(rcpi,(3u<<30)|(3u<<24),3u<<24);
        }
        for (uint32_t i=0;i<20 && !shouldStop();i++) {
            rmwA(MT_WTBL_UPDATE_REG,0x3ffu,i | (1u<<12));
            if (!pollA(MT_WTBL_UPDATE_REG,1u<<31,0,50)) return ITL_EIO;
        }
        const uint8_t enable[4]={1,0,0,0};
        rc=mcuSend(0x46ed,enable,sizeof(enable),true,&result);
        if (rc) return rc;
        uint8_t rts[12]={1,0,0,0}; put32(rts+4,0x92b); put32(rts+8,2);
        rc=mcuSend(0x3eed,rts,sizeof(rts),true,&result);
        if (rc) return rc;
        const uint8_t fwlog[4]={1,0,0,0};
        mcuSend(CE|0xc5,fwlog,sizeof(fwlog),false,nullptr);
        m3hw=true;
        m3log("Connac2 RX MAC/efuse/RTS ready; raw80211, both bands, group5 off");
    }
    static const uint16_t ch2[]={1,2,3,4,5,6,7,8,9,10,11,12,13};
    static const uint16_t ch5[]={36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};
    uint8_t domain[12+8*(13+25)]={};
    domain[0]='0'; domain[1]='0'; domain[4]=0; domain[5]=3; domain[6]=3;
    domain[8]=sizeof(ch2)/sizeof(ch2[0]); domain[9]=sizeof(ch5)/sizeof(ch5[0]);
    uint8_t *w=domain+12;
    for (unsigned i=0;i<sizeof(ch2)/sizeof(ch2[0]);i++,w+=8) put16(w,ch2[i]);
    for (unsigned i=0;i<sizeof(ch5)/sizeof(ch5[0]);i++,w+=8) put16(w,ch5[i]);
    int rc=mcuSend(CE|0x0f,domain,(size_t)(w-domain),false,nullptr);
    if (rc) return rc;
    uint8_t rx[76]={}; rx[0]=rx[1]=tgtCh?tgtCh:1; rx[3]=2; rx[4]=3;
    rx[10]=rx[0]>14?1:0;
    rc=mcuSend(0x4eed,rx,sizeof(rx),true,nullptr);
    if (rc) return rc;
    uint8_t filter[68]={}; filter[4]=1; put32(filter+8,(1u<<31)|(1u<<6));
    rc=mcuSend(CE|0x0a,filter,sizeof(filter),false,nullptr);
    if (rc) return rc;
    bzero(filter,sizeof(filter)); filter[4]=2; put32(filter+12,1u<<11); filter[16]=2;
    rc=mcuSend(CE|0x0a,filter,sizeof(filter),false,nullptr);
    if (rc) return rc;
    if (!clcCc[0] && !noPwr) return m3PowerSetup();
    return shouldStop() || firmwareFault ? ITL_EIO : 0;
}

// Power tables: CLC (world, indoor) + the SKU limits. Best effort: the firmware ran without them before (they were added without
// a hardware run and the efuse query failed on every join of the first one), so a failure must not abort the connection.
int itlmt7922::m3PowerSetup()
{
    sarInit();
    uint8_t encap=0;
    int er=efuseRead(0x55b,&encap);
    hwEncap=encap&1;
    int clc=er?er:m3Clc("00",1);
    if (clc) m3log("CLC unavailable rc=%d; applying explicit conservative SKU limits",clc);
    if (!clcCc[0]) { clcCc[0]='0'; clcCc[1]='0'; clcCc[2]=0; }
    int rc=m3TxPower();
    if (rc) m3log("SKU limit command failed rc=%d",rc);
    return rc;
}

// ---------------------------------------------------------------------------------------------
// BSS_INFO_UPDATE for the station interface (mt7922_mcu_add_bss_info_sta, non-MLD)
// ---------------------------------------------------------------------------------------------
int itlmt7922::m3Bss(bool enable)
{
    M3Msg m; m.init(4); m.b[0]=M3_BSS_IDX;
    uint8_t *b=m.tlv(0,32);
    b[4]=1; b[7]=0; put32(b+8,0x10001); b[12]=enable?0:1;
    memcpy(b+14,tgtBssid,6); put16(b+20,M3_BMC_WCID);
    put16(b+22,tgtBcnInt?tgtBcnInt:100); b[24]=1;
    const bool g2=tgtCh<=14;
    b[25]=g2?(0x02|0x04):0x01;
    uint16_t phy=g2?3:8;
    if (fastActive) { b[25]|=g2?0x08:(0x10|(apCaps.vht?0x20:0)); phy|=0x10|(apCaps.vht?0x20:0); }
    put16(b+26,M3_BMC_WCID); put16(b+28,phy);
    uint8_t *q=m.tlv(15,8); q[4]=1;
    m.b[2]=m.b[3]=0; // BSS header has reserved bytes, unlike STA's TLV count.
    int rc=m3Cmd(UNI_BSS_INFO_UPDATE,m.b,m.n,enable?"bss(enable)":"bss(add)");
    if (rc) return rc;
    // Connac2 RLM uses short_st@10, ht_op_info@11, sco@12, Linux band@13.
    m.init(4); m.b[0]=M3_BSS_IDX;
    uint8_t *r=m.tlv(2,16); r[4]=tgtCh; r[5]=fastActive?fastCenter:tgtCh;
    r[7]=fastActive?fastBw:0; r[8]=fastActive?2:1; r[9]=fastActive?3:1;
    r[10]=1; r[11]=r[7]?4:0; r[12]=r[4]<r[5]?1:r[4]>r[5]?3:0; r[13]=g2?0:1;
    m.b[2]=m.b[3]=0;
    rc=m3Cmd(UNI_BSS_INFO_UPDATE,m.b,m.n,"bss(rlm)");
    if (rc) return rc;
    // Initialize the BSS multicast WCID's nested WTBL before GTK installation.
    if (!enable) {
        m.init(8); m.b[0]=M3_BSS_IDX; m.b[1]=M3_BMC_WCID; m.b[4]=1; m.b[5]=0xe;
        uint8_t *outer=m.tlv(13,4+8+20+12+8);
        uint8_t *h=outer+4; h[0]=M3_BMC_WCID; h[1]=1; put16(h+2,3);
        uint8_t *g=h+8; put16(g,0); put16(g+2,20); memcpy(g+4,tgtBssid,6); g[10]=0xe;
        uint8_t *rx=g+20; put16(rx,1); put16(rx+2,12); rx[5]=rx[6]=rx[7]=1;
        uint8_t *tr=rx+12; put16(tr,6); put16(tr+2,8); tr[4]=1; tr[6]=1;
        rc=m3Cmd(UNI_STA_REC_UPDATE,m.b,m.n,"bmc(wtbl)");
        if (rc) return rc;
    }
    return m3Edca();
}

// ---------------------------------------------------------------------------------------------
// EDCA_UPDATE (mt7922_mcu_set_tx): contention parameters of the four access categories. Linux sends it after every BSS_INFO
// (BSS_CHANGED_QOS / add_interface); without it the firmware's AC queues kept whatever they start with, and the measured
// uplink was ~1.1 firmware retries per frame at -39 dBm, 1.7 MB/s.
// ---------------------------------------------------------------------------------------------
int itlmt7922::m3Edca()
{
    uint16_t aifs[4]={2,2,3,7}, cwMin[4]={3,7,15,15}, cwMax[4]={7,15,1023,1023}, txop[4]={47,94,0,0};
    static const uint8_t aciToAc[4]={2,3,1,0};
    for (const uint8_t *e=tgtIe,*end=tgtIe+tgtIeLen;e+2<=end && e+2+e[1]<=end;e+=2+e[1]) {
        if (e[0]!=0xdd || e[1]<24 || e[2]!=0 || e[3]!=0x50 || e[4]!=0xf2 || e[5]!=2 || e[6]!=1) continue;
        for (unsigned i=0;i<4;i++) {
            const uint8_t *r=e+10+4*i; uint8_t ac=aciToAc[(r[0]>>5)&3];
            aifs[ac]=r[0]&15; cwMin[ac]=(uint16_t)((1u<<(r[1]&15))-1); cwMax[ac]=(uint16_t)((1u<<(r[1]>>4))-1);
            txop[ac]=(uint16_t)(r[2]|(r[3]<<8));
        }
        break;
    }
    uint8_t req[44]={}; static const uint8_t toAci[4]={1,0,2,3};
    for (unsigned ac=0;ac<4;ac++) {
        uint8_t *e=req+toAci[ac]*10;
        put16(e,cwMin[ac]?cwMin[ac]:5); put16(e+2,cwMax[ac]?cwMax[ac]:10);
        put16(e+4,txop[ac]); put16(e+6,aifs[ac]);
    }
    req[40]=M3_BSS_IDX; req[41]=1;
    return mcuSend((1u<<18)|0x1d,req,sizeof(req),false,nullptr);
}

// ---------------------------------------------------------------------------------------------
// STA_REC_UPDATE for the AP (mt7922_mcu_sta_cmd, non-MLD station, legacy OFDM peer)
// state: 0 NONE, 1 AUTH, 2 ASSOC
// ---------------------------------------------------------------------------------------------
int itlmt7922::m3Sta(uint8_t state, bool newly, uint16_t aid)
{
    M3Msg m; m.init(8); m.b[0]=M3_BSS_IDX; m.b[1]=M3_AP_WCID; m.b[4]=1;
    uint8_t *b=m.tlv(0,20); put32(b+4,0x10002); b[8]=2; b[9]=1;
    put16(b+10,aid); memcpy(b+12,tgtBssid,6); put16(b+18,newly?3:1);
    bool ht=fastActive && state==2;
    if (ht) {
        uint8_t *h=m.tlv(9,8); put16(h+4,apCaps.htCap);
        if (apCaps.vht) { uint8_t *v=m.tlv(10,16); put32(v+4,apCaps.vhtCap); put16(v+8,apCaps.vhtRxMcs); put16(v+10,apCaps.vhtTxMcs); }
    }
    bool g2=tgtCh<=14;
    uint8_t *p=m.tlv(0x15,12);
    put16(p+4,g2?(uint16_t)(apBasicCck|(apBasic<<4)):apBasic);
    p[6]=(g2?3:8)|(ht?0x10:0)|(ht&&apCaps.vht?0x20:0);
    p[7]=ht?apCaps.ampduParm:0;
    p[9]=tgtRssi<0 && tgtRssi>=-110?(uint8_t)(2*(tgtRssi+110)):100;
    uint8_t *ra=m.tlv(1,16); put16(ra+4,(uint16_t)(apSupp<<6)|(g2?apCck:0));
    if (ht) memcpy(ra+6,apCaps.mcsRx,10);
    uint8_t *st=m.tlv(7,12); st[8]=state;
    if (ht&&apCaps.vht) st[9]=(uint8_t)(fastBw|((fastNss?fastNss-1:0)<<4));
    // STA_REC_WTBL nests its own header and count; Connac3 direct HDR_TRANS/MLD are invalid here.
    uint16_t outerStart=m.n;
    uint8_t *outer=m.tlv(13,12);
    uint8_t *wh=outer+4; wh[0]=M3_AP_WCID; wh[1]=1;
    uint16_t nested=0;
    auto wt=[&](uint16_t tag,uint16_t len)->uint8_t* {
        uint8_t *t=m.b+m.n; put16(t,tag); put16(t+2,len); m.n+=len; nested++; return t;
    };
    uint8_t *g=wt(0,20); memcpy(g+4,tgtBssid,6); g[10]=0; g[13]=1; put16(g+16,aid);
    uint8_t *rx=wt(1,12); rx[5]=rx[6]=rx[7]=1;
    uint8_t *tr=wt(6,8); tr[4]=1; tr[6]=1;
    if (ht) {
        uint8_t *h=wt(2,12); h[4]=1; h[5]=(apCaps.htCap&1)?1:0;
        const uint8_t htFactor=apCaps.ampduParm&3;
        const uint8_t vhtFactor=apCaps.vht?(uint8_t)((apCaps.vhtCap>>23)&7):0;
        // mt76_connac_mcu_wtbl_ht_tlv raises the shared WTBL aggregation
        // limit for VHT. Keeping only HT's two-bit factor caps VHT bursts.
        h[6]=vhtFactor>htFactor?vhtFactor:htFactor;
        h[7]=(apCaps.ampduParm>>2)&7;
        if (apCaps.vht) { uint8_t *v=wt(3,12); v[4]=(apCaps.vhtCap&(1u<<4))?1:0; v[6]=1; }
        m3log("WTBL aggregation ht_factor=%u vht_factor=%u selected=%u density=%u",
              htFactor,vhtFactor,h[6],h[7]);
        uint8_t *smps=wt(13,8); smps[4]=0;
    }
    put16(wh+2,nested); put16(outer+2,m.n-outerStart);
    char name[32]; snprintf(name,sizeof(name),"sta_connac2(st=%u)",state);
    return m3Cmd(UNI_STA_REC_UPDATE,m.b,m.n,name);
}

// ---------------------------------------------------------------------------------------------
// ROC (remain on channel) to be allowed to transmit auth / assoc on the AP's channel
// ---------------------------------------------------------------------------------------------
int itlmt7922::m3Roc(bool acquire)
{
    uint8_t req[4 + 24];
    bzero(req, sizeof(req));
    uint8_t *t = req + 4;
    if (acquire) {
        rocGrant = false;
        rocStatus = 0xff;
        rocTok++;
        put16(t + 0, 0);                                     // UNI_ROC_ACQUIRE
        put16(t + 2, 24);
        t[4] = M3_BSS_IDX;
        t[5] = rocTok;
        t[6] = tgtCh;                                        // control_channel
        t[7] = 0;                                            // sco
        t[8] = tgtCh > 14 ? 2 : 1;                           // band
        t[9] = 0;                                            // bw 20 MHz
        t[10] = tgtCh;                                       // center_chan
        t[12] = 0;                                           // bw_from_ap
        t[13] = tgtCh;                                       // center_chan_from_ap
        t[15] = 0;                                           // reqtype JOIN
        put32(t + 16, 5000);                                 // maxinterval (ms)
        t[20] = 0xff;                                        // dbdcband: auto
        return mcuSend((1u<<17)|UNI_ROC, req, sizeof(req), false, nullptr);
    }
    put16(t + 0, 1);                                         // UNI_ROC_ABORT
    put16(t + 2, 12);
    t[4] = M3_BSS_IDX;
    t[5] = rocTok;
    t[6] = 0xff;                                             // dbdcband
    return mcuSend((1u<<17)|UNI_ROC, req, 4 + 12, false, nullptr);
}

// ---------------------------------------------------------------------------------------------
// Management frame TX / RX (mt7922e_tx_prepare_skb + mt7922_mac_write_txwi, CT path with a token in the hw txp)
// ---------------------------------------------------------------------------------------------

// TXD (32) + hw txp (32) in the ring buffer, the 802.11 frame 128 bytes further; the ring entry covers TXD + txp only.
struct M3Lock {
    IOLock *l;
    explicit M3Lock(IOLock *x) : l(x) { if (l) IOLockLock(l); }
    ~M3Lock() { if (l) IOLockUnlock(l); }
};


// Looks for a management frame (header after the RXD groups) from the AP to us whose fc byte 0 is m3wantFc.

// Sends `frame` (up to 4 times, 150 ms apart) until a frame with fc byte 0 == wantFc comes back.
bool itlmt7922::m3Xchg(const uint8_t *frame, uint32_t len, uint8_t subtype, uint8_t wantFc, uint32_t waitMs)
{
    m3rxLen = 0;
    m3wantFc = wantFc;
    bool got = false;
    for (int attempt = 1; attempt <= 4 && !got && !shouldStop() && !firmwareFault; attempt++) {
        bool ok = m3Tx(frame, len, 0, subtype);
        m3log("tx %02x len=%u #%d %s", frame[0], len, attempt, ok ? "queued" : "FAILED");
        for (uint32_t i = 0; i < waitMs && !m3rxLen && !shouldStop() && !firmwareFault; i++) m3Pump(1);
        got = m3rxLen != 0;
    }
    m3wantFc = 0;
    if (!got) m3log("no response fc=%02x rxpk=%u txcpu=%u txdma=%u", wantFc, rxPkts, txData.head, rd(txData.regs + Q_DMA_IDX) & 0xffff);
    return got;
}

static void m3Hdr(uint8_t *h, uint8_t fc0, const uint8_t *bssid, const uint8_t *sa)
{
    bzero(h, 24);
    h[0] = fc0;
    memcpy(h + 4, bssid, 6);
    memcpy(h + 10, sa, 6);
    memcpy(h + 16, bssid, 6);
}

int itlmt7922::m3Auth()
{
    uint8_t f[30];
    m3Hdr(f, 0xb0, tgtBssid, mac);
    put16(f + 24, 0);                                            // open system
    put16(f + 26, 1);                                            // transaction 1
    put16(f + 28, 0);
    if (!m3Xchg(f, sizeof(f), 11, 0xb0, 150)) return ITL_TIMEOUT;
    uint16_t alg = (uint16_t)(m3rx[24] | (m3rx[25] << 8)), seq = (uint16_t)(m3rx[26] | (m3rx[27] << 8)),
             st = (uint16_t)(m3rx[28] | (m3rx[29] << 8));
    m3log("auth resp alg=%u seq=%u status=%u", alg, seq, st);
    return (alg == 0 && seq == 2 && st == 0) ? 0 : ITL_EIO;
}

int itlmt7922::m3Assoc()
{
    uint8_t f[320];
    m3Hdr(f, 0x00, tgtBssid, mac);
    uint8_t *p = f + 24;
    // 2.4 GHz: advertise the CCK rates the AP's basic set usually contains also on the legacy path (an AP whose basic rates are
    // 1/2/5.5/11 refuses a station that offers OFDM only)
    bool g2 = tgtCh <= 14;
    put16(p, g2 ? 0x0431 : 0x0411); p += 2;                     // ESS | PRIVACY | short slot (| short preamble on 2.4 GHz)
    put16(p, 10); p += 2;                                        // listen interval
    uint8_t sl = (uint8_t)strlen(m3ssid);
    *p++ = 0; *p++ = sl; memcpy(p, m3ssid, sl); p += sl;
    static const uint8_t rates[8] = {0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c};
    static const uint8_t rates2g[8] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};     // 1, 2, 5.5, 11 (CCK), 6, 9, 12, 18
    static const uint8_t ext2g[4] = {0x30, 0x48, 0x60, 0x6c};                               // 24, 36, 48, 54
    *p++ = 1; *p++ = 8; memcpy(p, g2 ? rates2g : rates, 8); p += 8;
    if (g2) { *p++ = 50; *p++ = 4; memcpy(p, ext2g, 4); p += 4; }
    static const uint8_t rsn[22] = {0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
                                    0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00};
    memcpy(p, rsn, sizeof(rsn)); p += sizeof(rsn);
    if (fastActive) {
        p += itl_caps_build_ht(p);
        if (apCaps.vht) p += itl_caps_build_vht(p, fastAllow160);
        if (fastHe) p += itl_caps_build_he(p, !g2, fastAllow160);
        static const uint8_t wmm[9] = {0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00};   // WMM information element: we are QoS-capable
        memcpy(p, wmm, sizeof(wmm)); p += sizeof(wmm);
    }
    if (!m3Xchg(f, (uint32_t)(p - f), 0, 0x10, 150)) return ITL_TIMEOUT;
    uint16_t st = (uint16_t)(m3rx[26] | (m3rx[27] << 8)), aid = (uint16_t)((m3rx[28] | (m3rx[29] << 8)) & 0x3fff);
    m3log("assoc resp status=%u aid=%u", st, aid);
    if (st) return ITL_EIO;
    m3aid = aid;
    return 0;
}

// ---------------------------------------------------------------------------------------------
// M3 sequence. Each step is added behind its own log line so a partial run is still informative.
// ---------------------------------------------------------------------------------------------
int itlmt7922::m3Run1()
{
    m3log("armed");
    m3stepDown = m3stepRadio = false;                        // per-attempt state (an earlier attempt may have failed half way)
    m3reachedAssoc = false;
    m3cipher = 0;
    m3dataOn = false;
    m3linkUp = false;
    m3wantEapol = false;
    m3eapolLen = 0;
    m3eapolHead = m3eapolTail = m3eapolDrops = 0;
    m3rxLen = 0;
    fastActive = false;
    txPool = true;

    // 0. credentials: the candidates m3Supervise() put in nets[] (a joined network, or itl_ssid / itl_psk .. itl_ssid4 / itl_psk4
    // from the personality in that order)
    Net *nets = candNets;
    int nn = candN;
    if (!nn) {
        m3log("no usable itl_ssid/itl_psk in the personality");
        m3Publish("nocred");
        return ITL_EINVAL;
    }
    m3log("credentials: %d network(s)", nn);
    for (int i = 0; i < nn; i++)
        m3log("net%d ssid len=%u psk len=%u", i + 1, (unsigned)strlen(nets[i].ssid), (unsigned)strlen(nets[i].psk));

    // The scan already ran (M2). m3Capture only keeps beacons of the SSID in m3ssid, so look for each configured network in turn
    // (directed probe request) until one is seen; a network that the wildcard scan already listed goes first.
    int order[4], no = 0;
    for (int pass = 0; pass < 2; pass++)
        for (int i = 0; i < nn; i++) {
            bool seen = false;
            for (int j = 0; j < nAps; j++) if (!strcmp(aps[j].ssid, nets[i].ssid)) seen = true;
            if (seen == (pass == 0)) order[no++] = i;
        }
    int sel = -1;
    for (int attempt = 1; attempt <= 3 && sel < 0 && !shouldStop() && !firmwareFault; attempt++) {
        for (int k = 0; k < no && sel < 0 && !shouldStop() && !firmwareFault && !cmdPending(CMD_JOIN | CMD_DISCONNECT); k++) {
            int i = order[k];
            strlcpy(m3ssid, nets[i].ssid, sizeof(m3ssid));
            tgtFound = false;
            // Prefer the beacon the passive scan already stored (works for DFS channels too, where an active probe is not
            // allowed); only probe when the AP was not heard in the last minute.
            if (m3UseCached(m3ssid, 60000)) {
                m3log("cached net%d ssid len=%u", i + 1, (unsigned)strlen(m3ssid));
                sel = i;
                break;
            }
            m3log("scan #%d for net%d (directed)", attempt, i + 1);
            m2Scan(m3ssid);
            for (int w = 0; w < 5 && !tgtFound && !shouldStop() && !firmwareFault; w++) { rxDataPoll(); IOSleep(100); }
            if (tgtFound) sel = i;
        }
    }
    m3Publish("scan");
    if (sel < 0) { m3log("no configured network seen in the scan"); return ITL_EIO; }
    strlcpy(m3ssid, nets[sel].ssid, sizeof(m3ssid));
    strlcpy(m3psk, nets[sel].psk, sizeof(m3psk));
    // candNets stays: the fall-back ladder in m3Run() calls this again for the next level; m3Supervise() wipes it afterwards
    m3log("selected net%d ssid len=%u", sel + 1, (unsigned)strlen(m3ssid));
    m3log("target %02x:%02x:%02x:%02x:%02x:%02x ch=%u cap=%04x bi=%u ies=%u", tgtBssid[0], tgtBssid[1], tgtBssid[2],
          tgtBssid[3], tgtBssid[4], tgtBssid[5], tgtCh, tgtCap, tgtBcnInt, tgtIeLen);

    // A level given up on 2.4 GHz says nothing about 5 GHz (and the other way round): another band starts from the top again.
    if (m3fast && capBand && capBand != (tgtCh <= 14 ? 1 : 2)) {
        evLog("band changed (cap learned on %s): level %u -> %u", capBand == 1 ? "2.4 GHz" : "5 GHz", lvl, fastLevel);
        lvlCap = 255;
        capBand = 0;
        lvl = fastLevel;
    }

    // PMK now (4096 PBKDF2 iterations), kept for the 4-way handshake; native Wi-Fi hands over the key its supplicant derived
    uint8_t pmk[32];
    if (nets[sel].hasPmk) memcpy(pmk, nets[sel].pmk, sizeof(pmk));
    else itl_wpa_pmk(m3psk, (const uint8_t *)m3ssid, strlen(m3ssid), pmk);
    memcpy(m3pmk, pmk, sizeof(m3pmk));
    bzero(pmk, sizeof(pmk));
    m3log("pmk ready");
    m3Publish("pmk");

    // step 2: firmware / hardware prep, BSS + STA records in the "not associated" state, ROC on the AP's channel
    m3ParseAp();
    int prepRc = m3HwPrep();
    if (prepRc) { m3Publish("hw-prep-fail"); return prepRc; }
    // Each setup step used to return without publishing anything, so every failure below looked like "connection failed"
    // with m3-res still on "pmk". Name the step, and never leave a ROC behind: the next attempt would fail the same way.
    const char *setupStage = "bss-fail";
    int setupRc = m3Bss(false);
    if (!setupRc) { setupStage = "sta-fail"; setupRc = m3Sta(0, true, 0); }
    if (!setupRc) { setupStage = "roc-setup-fail"; setupRc = m3Roc(true); }
    if (setupRc) {
        m3Publish(setupStage);
        evLog("setup failed: %s rc=%d", setupStage, setupRc);
        m3Roc(false);
        return setupRc;
    }
    for (int i = 0; i < 1000 && !rocGrant && !shouldStop() && !firmwareFault; i++) m3Pump(1);
    m3log("roc grant=%d status=%u", rocGrant ? 1 : 0, rocStatus);
    if (!rocGrant || rocStatus != 0) { m3Publish("roc-fail"); m3Roc(false); return ITL_EIO; }

    // step 3: open-system authentication and association, both on the channel held by the ROC
    m3log("sta mac %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    int rc = m3Auth();
    m3Publish(rc ? "auth-fail" : "auth-ok");
    if (!rc) {
        m3reachedAssoc = true;
        rc = m3Assoc();
        m3Publish(rc ? "assoc-fail" : "assoc-ok");
    }

    // step 4: BSS up, station state "associated", 4-way handshake with key install, Ethernet interface
    if (!rc) {
        rc=m3Bss(true);
        if (!rc) rc=m3Sta(2,false,m3aid);
        if (!rc) rc=m3Handshake();
        m3wantEapol = false;
        m3Publish(rc ? "hs-fail" : "hs-ok");
    }
    m3Roc(false);
    bzero(m3pmk, sizeof(m3pmk));
    if (!rc) {
        m3log("RESULT rc=0 link up");
        m3Link();                                            // returns only when this level has to be given up (m3stepDown)
        return ITL_EIO;
    }
    if (fastActive && lvl >= 1 && m3reachedAssoc) {         // association / handshake failed with HT/VHT: try one level lower
        m3stepDown = true;
        baLog("lvl %u: assoc/handshake rc=%d", lvl, rc);
        evLog("lvl %u: association/handshake failed rc=%d", lvl, rc);
    }
    return rc;
}

// The connection sequence with a fallback ladder: mt7922_fast=<level> is tried first; when it does not work (association or
// handshake rejected, or the link comes up but nothing unicast ever comes back) the driver leaves the AP and connects again
// one level lower, down to the legacy 6 Mb/s path that was verified on the reference machine.
int itlmt7922::m3Run()
{
    // start at the highest level that has not failed for this network in this session (lvlCap), not always at mt7922_fast
    lvl = m3fast ? (fastLevel < lvlCap ? fastLevel : lvlCap) : 0;
    for (; !shouldStop() && !firmwareFault;) {
        int rc = m3Run1();
        if (!m3stepDown || lvl == 0) return rc;
        uint8_t next = lvl - 1;
        const bool forced = lvlForce != 0;                   // run-time control (itl_lvl): exactly the level asked for
        if (forced) {
            next = lvlForce;
            lvlForce = 0;
        } else {
            // levels 4..6 add features only where the AP offers them: skip the ones that would repeat the configuration that just failed
            while (next >= 4 && fastSig(next) == fastSig(lvl)) next--;
            // RX Block Ack independently helps downloads: retain level 2
            // when falling back from a TX Block Ack failure at level 3.
        }
        baLog("level %u given up, connecting again at %u", lvl, next);
        evLog("level %u -> %u%s", lvl, next, forced ? " (asked for)" : m3stepRadio ? " (radio; next connection starts high again)" : "");
        m3Teardown();
        lvl = next;
        // A level the AP does not work with stays given up for this network. Failing transmissions are radio conditions
        // (distance, interference, a busy 160 MHz channel): run lower now, but let the next connection try the full level again,
        // instead of staying slow for the rest of the boot after one bad minute.
        if (!m3stepRadio || forced) {                        // (a level asked for at run time sticks: a re-join starts there too)
            lvlCap = next;
            capMs = nowMs() ? nowMs() : 1;
            capBand = tgtCh <= 14 ? 1 : 2;
        }
    }
    return ITL_EIO;
}

void itlmt7922::m3Teardown()
{
    m3linkUp = false;
    ethLink(false);
    if (shouldStop() || firmwareFault) { m3dataOn=false; return; }
    baReset();
    uint8_t f[26];
    m3Hdr(f, 0xc0, tgtBssid, mac);                           // deauthentication, reason 3: station is leaving
    put16(f + 24, 3);
    m3Tx(f, sizeof(f), 0, 12);
    IOSleep(100);
    m3Bss(false);                                            // BSS back to "not connected"
    m3Roc(false);                                            // an earlier attempt may have returned before releasing it
    m3dataOn = false;
    m3cipher = 0;
    IOSleep(100);
}

// ---------------------------------------------------------------------------------------------
// Step 4: data frames, 4-way handshake, keys, link
// ---------------------------------------------------------------------------------------------
static inline uint16_t be16p(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

// One record per Ethernet frame (ring of the last kFrRing): what went through just before the firmware stopped answering.
void itlmt7922::frameNote(char dir, const uint8_t *e, uint32_t len)
{
    if (len < 14) return;
    FrameRec &f = frRing[frHead++ % kFrRing];
    f.ms = nowMs();
    f.len = (uint16_t)len;
    f.dir = (uint8_t)dir;
    f.et = (uint16_t)(e[12] << 8 | e[13]);
    f.proto = 0;
    f.a = f.b = 0;
    if (f.et == 0x0806 && len >= 22) {
        f.a = e[21];                                         // ARP operation
    } else if (f.et == 0x0800 && len >= 34) {
        const uint8_t *ip = e + 14;
        uint32_t ihl = (ip[0] & 15) * 4;
        f.proto = ip[9];
        if ((f.proto == 17 || f.proto == 6) && len >= 14 + ihl + 4) {
            f.a = (uint16_t)(ip[ihl] << 8 | ip[ihl + 1]);
            f.b = (uint16_t)(ip[ihl + 2] << 8 | ip[ihl + 3]);
        } else if (f.proto == 1 && len > 14 + ihl) {
            f.a = ip[ihl];
        }
    }
}

// Everything that could explain a silent firmware, in one go (no secrets: registers, ring indices, frame kinds).
void itlmt7922::m3Postmortem(const char *tag)
{
    uint8_t cap = 0;
    uint16_t lnkCtl = 0xffff, lnkSta = 0xffff, cmd = pci->configRead16(kIOPCIConfigCommand), sta = pci->configRead16(kIOPCIConfigStatus);
    if (pci->findPCICapability(0x10, &cap) && cap) {
        lnkCtl = pci->configRead16(cap + 0x10);
        lnkSta = pci->configRead16(cap + 0x12);
    }
    uint32_t doneEvt = 0, doneDat = 0;
    for (int i = 0; i < rxEvt.n; i++) if (le32(rxEvt.desc.va + i * 16 + 4) & MT_DMA_CTL_DMA_DONE) doneEvt++;
    for (int i = 0; i < rxData.n; i++) if (le32(rxData.desc.va + i * 16 + 4) & MT_DMA_CTL_DMA_DONE) doneDat++;
    char b[700];
    snprintf(b, sizeof(b),
             "%s: chip=%08x lp=%08x misc=%08x dummy=%08x glo=%08x ints=%08x inte=%08x pci cmd=%04x sta=%04x lnkctl=%04x lnksta=%04x "
             "txwm %u/%u txdat %u/%u txfwdl %u/%u rxevt %u/%u t=%d done=%u/%d rxdat %u/%u t=%d done=%u/%d fwlog=%u ev=%u",
             tag, rdA(MT_HW_CHIPID), rdA(MT_CONN_ON_LPCTL), rdA(MT_CONN_ON_MISC), rdA(MT_WFDMA_DUMMY_CR), rdA(MT_WFDMA0_GLO_CFG),
             rdA(MT_WFDMA0_HOST_INT_STA), rdA(MT_WFDMA0_HOST_INT_ENA), cmd, sta, lnkCtl, lnkSta, rd(txWm.regs + Q_CPU_IDX),
             rd(txWm.regs + Q_DMA_IDX) & 0xffff, txData.n ? rd(txData.regs + Q_CPU_IDX) : 0,
             txData.n ? rd(txData.regs + Q_DMA_IDX) & 0xffff : 0, rd(txFwdl.regs + Q_CPU_IDX), rd(txFwdl.regs + Q_DMA_IDX) & 0xffff,
             rd(rxEvt.regs + Q_CPU_IDX), rd(rxEvt.regs + Q_DMA_IDX) & 0xffff, rxEvt.tail, doneEvt, rxEvt.n,
             rxData.n ? rd(rxData.regs + Q_CPU_IDX) : 0, rxData.n ? rd(rxData.regs + Q_DMA_IDX) & 0xffff : 0, rxData.tail, doneDat,
             rxData.n, fwLogCnt, evCount);
    m3log("postmortem %s", b);
    setProperty("wifi-postmortem", b);
    // the last frames, newest last: "<ms ago><t|r> <ethertype>/<proto> <a>><b> <len>"
    char fr[800];
    size_t o = 0;
    uint32_t now = nowMs();
    fr[0] = 0;
    uint32_t cnt = frHead < (uint32_t)kFrRing ? frHead : (uint32_t)kFrRing;
    for (uint32_t i = 0; i < cnt; i++) {
        const FrameRec &f = frRing[(frHead - cnt + i) % kFrRing];     // oldest first
        int n = snprintf(fr + o, sizeof(fr) - o, "%u%c %04x/%u %u>%u %u;", now - f.ms, f.dir, f.et, f.proto, f.a, f.b, f.len);
        if (n <= 0 || o + (size_t)n >= sizeof(fr)) break;
        o += (size_t)n;
    }
    setProperty("wifi-frames", fr);
}

// Redo what a cold start does (wfsys reset, rings, firmware, interface, first scan). Runs on the worker thread only.
bool itlmt7922::chipRecover()
{
    recoverCnt++;
    evLog("chip not answering: reset and firmware reload #%u", recoverCnt);
    m3log("recover #%u: wfsys reset, rings, firmware", recoverCnt);
    m3linkUp = false;
    m3dataOn = false;
    m3cipher = 0;
    ethStalled = false;
    fastActive = false;
    txPool = true;
    // Token ownership is retained until TXFREE or a quiesced hardware reset.
    m3hw = false;                                            // a reloaded firmware has none of the one-time setup (fw_log, efuse, RTS): redo it
    clcCc[0] = 0;                                            // ... nor the CLC / SKU power tables
    if (shouldStop() || !quiesceHardware()) return false;
    firmwareFault=false;
    int rc = m1Run();
    m3log("recover: M1 rc=%d", rc);
    if (!rc) {
        rc = m2Run();
        m3log("recover: M2 rc=%d", rc);
    }
    evLog("recover #%u rc=%d", recoverCnt, rc);
    return rc == 0;
}

// First few interesting packets (ARP, UDP incl. DHCP, ICMP) in either direction, to see how far traffic gets.
void itlmt7922::m3Note(const char *dir, const uint8_t *e, uint32_t len)
{
    frameNote(dir[0], e, len);
    if (stNote >= 24 || len < 34) return;
    uint16_t et = be16p(e + 12);
    if (et == 0x0806) {
        stNote++;
        m3log("%s arp op=%u", dir, e[21]);
    } else if (et == 0x0800) {
        const uint8_t *ip = e + 14;
        uint32_t ihl = (ip[0] & 15) * 4;
        if (ip[9] == 17 && len >= 14 + ihl + 8) {
            stNote++;
            m3log("%s udp %u>%u len=%u", dir, be16p(ip + ihl), be16p(ip + ihl + 2), len);
        } else if (ip[9] == 1 && len > 14 + ihl) {
            stNote++;
            m3log("%s icmp type=%u", dir, ip[ihl]);
        }
    }
}

// ---- receive: Ethernet frames to the stack, through the reorder buffer of the TID when there is one ----
void itlmt7922::m3Hex(char *out, size_t outLen, const uint8_t *p, uint32_t n)
{
    static const char hx[] = "0123456789abcdef";
    size_t k = 0;
    for (uint32_t i = 0; i < n && k + 3 < outLen; i++) { out[k++] = hx[p[i] >> 4]; out[k++] = hx[p[i] & 15]; }
    out[k] = 0;
}

// Hands the frames collected for one MPDU to the reorder buffer (or, if the agreement is gone, to the stack).
void itlmt7922::amsduFlush()
{
    AmsduAsm &a = amsduAsm;
    if (!a.active) return;
    a.active = false;
    uint32_t used = a.used;
    a.used = 0;
    if (rxBa[a.tid].r.active) itl_reorder_rx(&rxBa[a.tid].r, a.sn, used ? a.buf : nullptr, used, nowMs(), baDeliverCb, this);   // used == 0 still takes up the sequence number
    else if (used) itl_bundle_each(a.buf, used, ethDeliverCb, this);
}

void itlmt7922::rxStore(const uint8_t *eb, uint32_t n, bool reorder, uint8_t tid, uint16_t sn, bool last)
{
    AmsduAsm &a = amsduAsm;
    szParsed[szClass(n)]++;
    if (isBigEcho(eb, n, 0)) icmpRepParsed++;
    if (!reorder) {
        amsduFlush();
        ethDeliver(eb, n);
        return;
    }
    if (a.active && (a.tid != tid || a.sn != sn)) amsduFlush();
    if (!a.active) { a.active = true; a.tid = tid; a.sn = sn; a.used = 0; a.t = nowMs(); }
    uint32_t u = itl_bundle_add(a.buf, sizeof(a.buf), a.used, eb, n);
    if (u == a.used) { stRxDrop++; stBundleOvf++; } else a.used = u;
    if (last) amsduFlush();
}

// The body of an A-MSDU subframe packet: [2 bytes pad when the hardware split the A-MSDU] then the subframes (itl_amsdu_each); a
// whole A-MSDU the hardware left alone has no pad. Returns the frames unpacked.
struct M3AmsduCtx { itlmt7922 *d; bool reorder; uint8_t tid; uint16_t sn; uint32_t good; };

void itlmt7922::amsduFrameCb(void *ctx, const uint8_t *da, const uint8_t *sa, uint16_t et, const uint8_t *pl, uint32_t pn)
{
    M3AmsduCtx *x = (M3AmsduCtx *)ctx;
    itlmt7922 *d = x->d;
    static uint8_t eb[14 + 1600];
    if (memcmp(sa, d->mac, 6) == 0) return;                                  // our own broadcast echoed back
    memcpy(eb, da, 6);
    memcpy(eb + 6, sa, 6);
    eb[12] = (uint8_t)(et >> 8); eb[13] = (uint8_t)et;
    memcpy(eb + 14, pl, pn);
    if (!(da[0] & 1)) d->stRxUni++;
    x->good++;
    d->rxStore(eb, 14 + pn, x->reorder, x->tid, x->sn, false);
}

uint32_t itlmt7922::m3RxAmsdu(const uint8_t *b, uint32_t n, uint8_t ai, bool reorder, uint8_t tid, uint16_t sn)
{
    M3AmsduCtx x = { this, reorder, tid, sn, 0 };
    if (reorder) {
        // a new MPDU (first subframe, or another sequence number) closes the previous bundle; an MPDU whose subframes all fail
        // to parse still has to take up its sequence number, so the bundle is opened before parsing
        if (amsduAsm.active && (ai == 3 || amsduAsm.tid != tid || amsduAsm.sn != sn)) amsduFlush();
        if (!amsduAsm.active) { amsduAsm.active = true; amsduAsm.tid = tid; amsduAsm.sn = sn; amsduAsm.used = 0; amsduAsm.t = nowMs(); }
    }
    // The Connac2 data codec has already removed the hardware A-MSDU pad.
    // Parse exactly that normalized body; do not search alternate offsets.
    uint32_t found = itl_amsdu_each(b, n, 1600, amsduFrameCb, &x);
    if (found > x.good) stRxBigDrop += found - x.good;
    // Connac2 payload format 0 is a complete MPDU, and 1 its last split
    // subframe. Both close the bundle immediately; first/middle stay open.
    if (reorder && mt7922_amsdu_complete(ai)) amsduFlush();
    return x.good;
}

// RX data frame from the AP (802.11 header + LLC/SNAP after the RXD groups; header translation is off, decryption is done by
// the hardware once the keys are installed). EAPOL goes to the handshake, everything else to the Ethernet interface.
// The header sits after up to 32 + 4 x 16 + 96 bytes of RXD groups (mt7922_mac_fill_rx), so look for it from byte 32 on.

bool itlmt7922::m3TxData(const uint8_t *da, uint16_t ethertype, const uint8_t *payload, uint32_t plen, bool protect, bool *full)
{
    uint8_t f[34 + 1560];
    if (plen > 1560) return false;
    // With HT/VHT negotiated, unicast data (not the EAPOL handshake) goes out as QoS data (TID 0) at the rate the firmware
    // chooses; group-addressed frames and everything else keep the fixed basic rate.
    bool ra = fastActive && m3linkUp && ethertype != 0x888e && !(da[0] & 1);
    uint32_t hl = ra ? 26 : 24;
    bzero(f, hl);
    f[0] = ra ? 0x88 : 0x08;                                 // data / QoS data
    f[1] = protect ? 0x41 : 0x01;                            // To DS (+ Protected: the hardware adds the CCMP header)
    memcpy(f + 4, tgtBssid, 6);
    memcpy(f + 10, mac, 6);
    memcpy(f + 16, da, 6);                                   // QoS control (bytes 24-25) stays 0: TID 0, normal ack
    M3TxOpt o;
    o.protect = protect;
    o.rateAdapt = ra;
    o.full = full;
    if (ra) o.qidx = 1; // Connac2 AC_BE mapping applies before TX Block Ack too.
    uint16_t sn = txSn;
    if (ra && lvl >= 3) {
        // Level 3: access-category queue (AC_BE -> LMAC queue 1, mt76_connac_lmac_mapping), sequence numbers chosen here so that the
        // starting sequence number of the ADDBA request is known, and A-MPDU once the agreement is up.
        o.qidx = 1;
        o.sn = sn;
        o.aggr = txBaState == TXBA_ON;
        f[22] = (uint8_t)((sn & 0xf) << 4);                  // sequence control: SN << 4, fragment 0
        f[23] = (uint8_t)(sn >> 4);
    }
    static const uint8_t llc[6] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00};
    memcpy(f + hl, llc, 6);
    f[hl + 6] = (uint8_t)(ethertype >> 8); f[hl + 7] = (uint8_t)ethertype;
    memcpy(f + hl + 8, payload, plen);
    bool ok = m3Tx(f, hl + 8 + plen, 2, ra ? 8 : 0, o);
    if (ok && ra) {
        stTxUni++;
        if (lvl >= 3) txSn = itl_sn_inc(sn);                 // only a frame that really went out uses up a sequence number
    }
    return ok;
}

// Ethernet frame from the network stack (output queue thread): 0 sent, 1 TX pool full (retried after ethTxKick()), -1 dropped
int itlmt7922::ethTx(const uint8_t *e, uint32_t len)
{
    if (!m3linkUp || len < 14) return -1;
    bool full = false;
    bool ok = m3TxData(e, be16p(e + 12), e + 14, len - 14, true, &full);
    if (full) return 1;
    if (isBigEcho(e, len, 8)) icmpReqTx++;
    if (ok) stTx++; else stTxFail++;
    m3Note("tx", e, len);
    return ok ? 0 : -1;
}

// STA_REC_KEY_V3 (mt7922_mcu_sta_key_tlv): CCMP key on the AP's wcid (pairwise) or on the BSS's broadcast wcid (group)
int itlmt7922::m3Key(uint16_t wcid, bool pairwise, uint8_t keyId, const uint8_t *key, uint8_t keyLen)
{
    if (!key || keyLen!=16 || wcid>19) return ITL_EINVAL;
    M3Msg m; m.init(8); m.b[0]=M3_BSS_IDX; m.b[1]=(uint8_t)wcid; m.b[4]=1; m.b[5]=pairwise?0:0xe;
    uint8_t *s=m.tlv(0x11,44); // STA_REC_KEY_V2, one 36-byte sec_key
    s[4]=0; s[5]=1; s[8]=5; // SET_KEY=0, one cipher, MCU_CIPHER_AES_CCMP=5 (RXD SEC_MODE uses4)
    s[9]=36; s[10]=keyId; s[11]=keyLen; memcpy(s+12,key,keyLen);
    int rc=m3Cmd(UNI_STA_REC_UPDATE,m.b,m.n,pairwise?"key_v2(ptk)":"key_v2(gtk)");
    bzero(m.b,sizeof(m.b)); return rc;
}

// Preserve every complete key frame in a poll batch. The previous single mailbox silently
// discarded M3 when a retransmitted M1 happened to arrive first in the same batch.
bool itlmt7922::m3Eapol(const uint8_t *p, uint32_t len)
{
    itl_eapol_key k;
    int rc = itl_eapol_parse(p, len, &k);
    if (rc) { m3log("eapol rx rejected parse=%d len=%u", rc, len); return false; }
    uint32_t n = 4u + be16p(p + 2);
    if (n > sizeof(m3eapol) || m3eapolHead - m3eapolTail >= kEapolQueue) {
        m3eapolDrops++;
        m3log("eapol rx dropped len=%u depth=%u drops=%u", n, m3eapolHead - m3eapolTail, m3eapolDrops);
        return false;
    }
    EapolRx &r = m3eapolQueue[m3eapolHead++ % kEapolQueue];
    r.len = n;
    memcpy(r.data, p, n);
    return true;
}

bool itlmt7922::m3EapolNext()
{
    if (m3eapolTail == m3eapolHead) return false;
    EapolRx &r = m3eapolQueue[m3eapolTail++ % kEapolQueue];
    m3eapolLen = r.len;
    memcpy(m3eapol, r.data, r.len);
    bzero(&r, sizeof(r));
    return true;
}

int itlmt7922::m3Handshake()
{
    static const uint8_t rsnIe[22] = {0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
                                      0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00};
    uint8_t snonce[32], zero[32], replay[8] = {}, anonce[32] = {}, out[160], kd[8 * 40];
    itl_eapol_key k;
    itl_ptk ptk = {};
    bzero(zero, sizeof(zero));
    read_random(snonce, sizeof(snonce));
    m3dataOn = true;
    m3eapolLen = 0;
    m3eapolHead = m3eapolTail = m3eapolDrops = 0;
    m3hsApLeave = false;
    m3hsApReason = 0;
    removeProperty("wifi-pmkid-match");
    removeProperty("wifi-handshake");
    m3wantEapol = true;

    bool have1 = false, got3 = false;
    uint32_t m1Count = 0, m2Count = 0, badMic = 0, rejected = 0;
    uint32_t started = nowMs(), phaseStart = started, lastM2 = 0;
    uint32_t rxBefore = stRxEapol, freeBefore = stTxFree, failBefore = stTxFwFail;
    size_t n2 = 0;
    auto sendM2 = [&]() {
        bool ok = m3TxData(tgtBssid, 0x888e, out, (uint32_t)n2, false);
        m2Count++;
        lastM2 = nowMs();
        m3log("eapol m2 #%u queued=%u replay=%02x%02x%02x%02x%02x%02x%02x%02x", m2Count, ok,
              replay[0], replay[1], replay[2], replay[3], replay[4], replay[5], replay[6], replay[7]);
    };
    // Six seconds for M1 and, after the first M1, six for M3. Retransmitted M1s
    // do not extend the deadline. Each one gets a response with ITS counter and ANonce.
    while ((uint32_t)(nowMs() - phaseStart) < 6000 && !got3 && !m3hsApLeave && !shouldStop() && !firmwareFault) {
        m3Pump(1);
        if (m3hsApLeave) break;
        while (m3EapolNext()) {
            int rc = itl_eapol_parse(m3eapol, m3eapolLen, &k);
            if (rc) { rejected++; continue; }
            m3log("eapol rx info=%04x len=%u replay=%02x%02x%02x%02x%02x%02x%02x%02x",
                  k.info, m3eapolLen, k.replay[0], k.replay[1], k.replay[2], k.replay[3],
                  k.replay[4], k.replay[5], k.replay[6], k.replay[7]);
            const uint16_t required = ITL_KI_PAIRWISE | ITL_KI_ACK;
            if ((k.info & ITL_KI_VER_MASK) != 2 || (k.info & required) != required ||
                (k.info & (ITL_KI_ERROR | ITL_KI_REQUEST))) {
                rejected++;
                m3log("eapol rejected unsupported flags=%04x", k.info);
                continue;
            }
            if (!(k.info & ITL_KI_MIC) && !(k.info & ITL_KI_INSTALL)) {
                int cmp = have1 ? memcmp(k.replay, replay, 8) : 1;
                if (cmp < 0 || (have1 && cmp == 0 && memcmp(k.nonce, anonce, 32))) {
                    rejected++;
                    m3log("eapol m1 rejected stale/inconsistent replay");
                    continue;
                }
                if (!have1) {
                    phaseStart = nowMs();
                    // An AP may include its PMKID in M1. Compare without publishing either
                    // key or hash: this separates a PMK/station-identity mismatch from lost M2/M3.
                    bool pmkidPresent = false;
                    const uint8_t *e = k.data, *end = k.data + k.datalen;
                    for (; e + 2 <= end && e + 2 + e[1] <= end; e += 2 + e[1]) {
                        if (e[0] != 0xdd || e[1] != 20 || e[2] != 0 || e[3] != 0x0f || e[4] != 0xac || e[5] != 4) continue;
                        uint8_t name[20], hash[20], diff = 0;
                        memcpy(name, "PMK Name", 8);
                        memcpy(name + 8, tgtBssid, 6);
                        memcpy(name + 14, mac, 6);
                        itl_hmac_sha1(m3pmk, 32, name, sizeof(name), nullptr, 0, hash);
                        for (int i = 0; i < 16; i++) diff |= hash[i] ^ e[6 + i];
                        setProperty("wifi-pmkid-match", diff == 0);
                        m3log("eapol m1 PMKID present match=%u", diff == 0);
                        bzero(hash, sizeof(hash));
                        pmkidPresent = true;
                        break;
                    }
                    if (!pmkidPresent) m3log("eapol m1 PMKID absent");
                }
                bool changed = !have1 || memcmp(anonce, k.nonce, 32);
                memcpy(replay, k.replay, 8);
                memcpy(anonce, k.nonce, 32);
                if (changed) itl_wpa_ptk(m3pmk, tgtBssid, mac, anonce, snonce, &ptk);
                have1 = true;
                m1Count++;
                n2 = itl_eapol_build(out, 0x010a, 0, replay, snonce, rsnIe, sizeof(rsnIe));
                itl_eapol_mic(ptk.kck, out, n2);
                m3log("eapol m1 #%u anonceChanged=%u", m1Count, changed);
                sendM2();
                continue;
            }
            if (!have1 || (k.info & (ITL_KI_MIC | ITL_KI_INSTALL)) != (ITL_KI_MIC | ITL_KI_INSTALL)) {
                rejected++;
                m3log("eapol rejected unexpected state/flags");
                continue;
            }
            if (memcmp(k.replay, replay, 8) <= 0 || memcmp(k.nonce, anonce, 32)) {
                rejected++;
                m3log("eapol m3 rejected replay/ANonce");
                continue;
            }
            uint32_t elen = 4u + be16p(m3eapol + 2);
            if (!itl_eapol_mic_ok(ptk.kck, m3eapol, elen)) {
                badMic++;
                m3log("eapol m3 MIC rejected count=%u", badMic);
                continue;
            }
            got3 = true;
            break;  // k.data points into m3eapol: do not pop another frame before GTK processing.
        }
        if (!got3 && have1 && (uint32_t)(nowMs() - lastM2) >= 1500) sendM2();
    }
    char summary[200];
    snprintf(summary, sizeof(summary), "m1=%u m2=%u m3=%u rx=%u micBad=%u reject=%u drop=%u txFree=%u txFail=%u apLeave=%u reason=%u ms=%u",
             m1Count, m2Count, got3, stRxEapol - rxBefore, badMic, rejected, m3eapolDrops,
             stTxFree - freeBefore, stTxFwFail - failBefore, m3hsApLeave, m3hsApReason, nowMs() - started);
    setProperty("wifi-handshake", summary); // survives saturation of the older 3 KB m3-log
    m3log("eapol summary %s", summary);
    if (!got3) {
        bzero(&ptk, sizeof(ptk));
        bzero(snonce, sizeof(snonce));
        m3log("eapol: %s", have1 ? "no valid msg3" : "no msg1");
        evLog("handshake failed: %s", summary);
        return (badMic || m3hsApLeave) ? ITL_EIO : ITL_TIMEOUT;
    }
    m3log("eapol m3 info=%04x mic ok datalen=%u", k.info, k.datalen);

    // key data: wrapped RSN IE + GTK KDE
    uint8_t gtk[32], gtkId = 0, gtkLen = 0;
    if ((k.info & ITL_KI_ENCRYPTED) && k.datalen >= 24 && k.datalen <= sizeof(kd) + 8 &&
        itl_aes128_unwrap(ptk.kek, k.data, k.datalen, kd) == 0) {
        const uint8_t *e = kd, *end = kd + k.datalen - 8;
        while (e + 2 <= end && e + 2 + e[1] <= end) {
            if (e[0] == 0xdd && e[1] >= 22 && e[2] == 0x00 && e[3] == 0x0f && e[4] == 0xac && e[5] == 1) {
                gtkLen = (uint8_t)(e[1] - 6);
                if (gtkLen > sizeof(gtk)) gtkLen = 0;
                else { gtkId = e[6] & 3; memcpy(gtk, e + 8, gtkLen); }
                break;
            }
            e += 2 + e[1];
        }
    } else {
        m3log("eapol: key data not usable (info=%04x len=%u)", k.info, k.datalen);
    }
    m3log("gtk id=%u len=%u", gtkId, gtkLen);
    if (gtkLen != 16) return ITL_EIO;

    // msg4: ver 2 | pairwise | MIC | secure
    uint8_t replay3[8];
    memcpy(replay3, k.replay, 8);
    size_t n4 = itl_eapol_build(out, 0x030a, 0, replay3, zero, nullptr, 0);
    itl_eapol_mic(ptk.kck, out, n4);
    bool ok = m3TxData(tgtBssid, 0x888e, out, (uint32_t)n4, false);
    m3log("eapol m4 tx %s", ok ? "queued" : "FAILED");
    for (int i = 0; i < 30; i++) m3Pump(1);                    // let it go out in the clear before the keys arrive

    m3cipher = 4;
    int bssRc = ok ? m3Bss(true) : ITL_EIO;
    int r1 = bssRc ? bssRc : m3Key(M3_AP_WCID, true, 0, ptk.tk, 16);
    int r2 = r1 ? r1 : m3Key(M3_BMC_WCID, false, gtkId, gtk, 16);
    memcpy(m3ptk, &ptk, sizeof(m3ptk));
    bzero(&ptk, sizeof(ptk));
    bzero(gtk, sizeof(gtk));
    bzero(kd, sizeof(kd));
    return (r1 || r2) ? ITL_EIO : 0;
}

// Link is up: expose the Ethernet interface and keep servicing the receive rings. Returns only to give up the current fast level.
void itlmt7922::m3Link()
{
    bool eok = nativeMode || eth || ethCreate();
    m3log("%s interface %s", nativeMode ? "native" : "ethernet", eok ? "ready" : "FAILED");
    if (!eok) {
        m3linkUp=false; m3dataOn=false;
        strlcpy(m3lostWhy,"network interface creation failed",sizeof(m3lostWhy));
        m3Publish("interface-fail");
        wifiState("failed",m3lostWhy);
        return;
    }
    baReset();
    txSn = 0;
    rxLastValid = 0;
    stRxDupL = 0;
    stRxRetry = stRxPkt = 0;
    stRxUni = stTxUni = 0;
    stAmsduPkt = stAmsduSub = stAmsduBad = 0;
    txfWinFree = stTxFree;
    txfWinFail = stTxFwFail;
    txfBad = 0;
    uint32_t lastTxf = nowMs();
    m3linkUp = true;
    m3sleepy = true;
    uint32_t t0 = nowMs(), lastStat = 0, lastActive = t0;
    linkUpMs = t0;
    lastReorderMs = t0;
    m3lost = false;
    tgtLastBcnMs = 0;                                        // beacon watch is armed by the first beacon of this link
    lastRxDataMs = t0;
    tgtRssi = 0;
    wifiState("connected", "");
    wifiLink();
    if (njState == ITL_NATIVE_CONNECTING) njState = ITL_NATIVE_UP;   // the join the Family asked for (before its link callback)
    // Native publication may wake DHCP immediately. Radio TX/session state
    // must already be ready before entering the Family link transition.
    ethLink(true);
    evLog("up lvl %u ch %u bw %u", lvl, tgtCh, fastActive ? fastBw : 0);
    bool watchdogDone = false, silenceDone = false;
    for (; !shouldStop() && !firmwareFault;) {
        int act = m3PumpOnce();
        uint32_t now = nowMs();
        if (cmdPending(CMD_SCAN)) {                          // scan on the link: the firmware returns to the AP's channel between dwells
            cmdTake(CMD_SCAN, nullptr);
            wifiScan();
            wifiState("connected", "");
            now = nowMs();
        }
        if (cmdPending(CMD_JOIN | CMD_DISCONNECT)) {         // another network, or off: m3Supervise() takes it from here
            m3log("link: leaving for a command");
            m3Teardown();
            return;
        }
        if (ctlLvl || ctlPwr) ctlPoll();
        tsSample(now);
        if (!silenceDone && tgtLastBcnMs && now - tgtLastBcnMs > 4000 && now - lastRxDataMs > 4000) {
            // No beacon for 4 s (the AP sends ten a second): snapshot, then take driver ownership again in case the firmware
            // went to sleep on its own, and snapshot once more to see whether that changed anything.
            silenceDone = true;
            m3Postmortem("silent 4s");
            bool own = driverOwn();
            evLog("silent for 4 s: driverOwn=%d", own ? 1 : 0);
            IOSleep(50);
            m3Postmortem("after driverOwn");
        }
        if (!m3lost && tgtLastBcnMs && now - tgtLastBcnMs > 15000 && now - lastRxDataMs > 15000) {
            snprintf(m3lostWhy, sizeof(m3lostWhy), "no beacon or data from the AP for 15 s");
            m3lost = true;
        }
        if (m3lost) {
            m3log("link lost: %s", m3lostWhy);
            evLog("lost after %us at lvl %u: %s", (now - t0) / 1000, lvl, m3lostWhy);
            m3Postmortem("lost");
            recoverWanted = true;                            // the supervisor resets the chip once the link state is torn down
            m3Teardown();
            return;
        }
        baService();
        if (ethStalled && now - ethStallMs >= 20) { ethStalled = false; ethTxKick(); }   // no TXFREE came: retry (txSlotAlloc reclaims)
        if (amsduAsm.active && now - amsduAsm.t >= 4) amsduFlush();      // the last subframe of an A-MSDU never came
        if (now - lastReorderMs >= 10) {                     // frames waiting behind a hole in a Block Ack window for too long
            lastReorderMs = now;
            for (int t = 0; t < 8; t++)
                if (rxBa[t].r.active) itl_reorder_tick(&rxBa[t].r, now, reoMs, baDeliverCb, this);
        }
        ethFlush();
        uint32_t up = (now - t0) / 1000;
        if (fastActive && !watchdogDone && up >= 15) {
            watchdogDone = true;
            if (!stRxUni && stTx >= 2) {                     // we transmitted, and no unicast frame ever came back: HT/VHT is not working
                baLog("lvl %u: no unicast rx in %us (tx=%u rxd=%u eth=%u)", lvl, up, stTx, stRxData, stRxEth);
                evLog("lvl %u: no unicast frame received in %us tx=%u fail=%u fwfail=%u free=%u rxd=%u eapol=%u eth=%u", lvl, up,
                      stTx, stTxFail, stTxFwFail, stTxFree, stRxData, stRxEapol, stRxEth);
                m3stepDown = true;
            }
        }
        if (fastAmsdu && ((stAmsduPkt >= 8 && !stAmsduSub) || (stAmsduBad >= 32 && stAmsduBad * 4 > stAmsduSub))) {
            baLog("lvl %u: A-MSDUs cannot be unpacked (pkt=%u sub=%u bad=%u)", lvl, stAmsduPkt, stAmsduSub, stAmsduBad);
            evLog("lvl %u: A-MSDUs cannot be unpacked", lvl);
            m3stepDown = true;
        }
        if (txPool && now - lastTxf >= 5000) {                           // nearly every transmission reported failed by the firmware, twice in a row
            lastTxf = now;
            uint32_t df = stTxFree - txfWinFree, dx = stTxFwFail - txfWinFail;
            txfWinFree = stTxFree;
            txfWinFail = stTxFwFail;
            if (df >= 30 && dx * 10 >= df * 8) {
                if (++txfBad >= 2) {
                    baLog("lvl %u: tx failing (freed=%u failed=%u in 5 s)", lvl, df, dx);
                    evLog("lvl %u: tx failing, %u of %u frames in 5 s, rssi %d", lvl, dx, df, tgtRssi);
                    m3stepDown = m3stepRadio = true;
                }
            } else {
                txfBad = 0;
            }
        }
        if (up >= lastStat + (statSecs ? statSecs : (up < 300 ? 5 : 60))) {
            lastStat = up;
            uint32_t ri = 0, rd_ = 0, rb = 0, rdup = 0, rold = 0, rfl = 0, rto = 0, rlate = 0;
            for (int t = 0; t < 8; t++) {
                ri += rxBa[t].r.nIn; rd_ += rxBa[t].r.nDirect; rb += rxBa[t].r.nBuffered; rdup += rxBa[t].r.nDup;
                rold += rxBa[t].r.nOld; rfl += rxBa[t].r.nFlushed; rto += rxBa[t].r.nTimeout; rlate += rxBa[t].r.nLate;
            }
            char st[400];
            snprintf(st, sizeof(st),
                     "up=%us L%u rxd=%u eapol=%u eth=%u drop=%u tx=%u fail=%u rxpk=%u uni=%u/%u ba=%u/%u reo=%u/%u/%u/%u/%u/%u/%u/%u txf=%u/%u/%u/%u/%u am=%u/%u/%u/%u rty=%u/%u bw=%u",
                     up, lvl, stRxData, stRxEapol, stRxEth, stRxDrop, stTx, stTxFail, rxPkts, stRxUni, stTxUni, stBaRxOn, stBaTxOn, ri, rd_,
                     rb, rdup, rold, rfl, rto, rlate, stTxFree, stTxReclaim, stTxNoSlot, stTxFwFail, stTxFwRetry, stAmsduPkt, stAmsduSub, stAmsduBad,
                     stRxBigDrop, stRxRetry, stRxPkt, fastActive ? fastBw : 0);
            nvramStat(st);
            nvramChunks(m3buf);
            wifiLink();
        }
        if (m3stepDown) return;
        if (!fastActive) { IOSleep(1); continue; }           // legacy path: exactly as verified (1 ms poll)
        if (act) { lastActive = now; IODelay(20); }
        else if (now - lastActive < 50) IODelay(200);       // traffic is bursty (A-MPDUs): keep polling closely for a while
        else IOSleep(1);
    }
}
