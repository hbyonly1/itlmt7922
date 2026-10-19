// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (c) 2026 thanhnndev and contributors; MediaTek Inc. protocol references.
// Connac2 scan/capability/receive port; 36-byte events and packed CE scan.
#include "itlmt7922.hpp"
#include "mt7922_regs.h"
#include "../codec/mt7922_rx_codec.h"
#include <string.h>
#include <stdarg.h>
#include <libkern/libkern.h>
static inline uint32_t le32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static inline uint16_t le16(const uint8_t *p) { return (uint16_t)((uint32_t)p[0]|(uint32_t)p[1]<<8); }
static inline void put16(uint8_t *p,uint16_t v) { memcpy(p,&v,2); }
static inline void put32(uint8_t *p,uint32_t v) { memcpy(p,&v,4); }
static inline void barrier() { __sync_synchronize(); }
static const uint32_t kCe=1u<<18,kUni=1u<<17,kQuery=1u<<16;
// 2.4 GHz + 5 GHz non-DFS, exactly the list that was verified on hardware: a DFS channel in this request could make the
// firmware reject the whole scan, so the DFS block is kept apart and scanned in a second passive pass (5 GHz hotspots whose
// channel is on DFS never showed up in the scan at all). The request carries at most 32 channel entries.
static const uint8_t chans[][2]={{1,1},{1,2},{1,3},{1,4},{1,5},{1,6},{1,7},{1,8},{1,9},{1,10},{1,11},{1,12},{1,13},
 {2,36},{2,40},{2,44},{2,48},{2,149},{2,153},{2,157},{2,161},{2,165}};
static const uint8_t chansDfs[][2]={{2,52},{2,56},{2,60},{2,64},
 {2,100},{2,104},{2,108},{2,112},{2,116},{2,120},{2,124},{2,128},{2,132},{2,136},{2,140},{2,144}};

bool itlmt7922::ringPeek(itl_ring &r,const uint8_t **data,uint32_t *length,int *index)
{
    if (!r.n || !r.desc.va || !r.buf.va || r.tail==r.head) return false;
    const uint32_t ctrl=le32(r.desc.va+r.tail*16+4);
    if (!(ctrl & MT_DMA_CTL_DMA_DONE)) return false;
    barrier();
    const unsigned ring=&r==&rxEvt?0:&r==&rxWa?1:&r==&rxData?2:3;
    int bi=r.slotBuf[r.tail];
    if (bi<0 || bi>=r.n) {
        // An invalid mapping cannot safely be consumed/refilled. This counts
        // failed observations, since a later poll may encounter it again.
        if (ring<3) rxDmaBadIndex[ring]++;
        return false;
    }
    *index=bi; *data=r.buf.va+(size_t)bi*MT_RX_BUF_SIZE;
    *length=(ctrl>>16)&0x3fff;
    if (ring<3) {
        rxDmaDesc[ring]++;
        // These are independent raw-descriptor categories: a descriptor can
        // be both oversized and non-final. No fragment reassembly is added.
        if (!*length) rxDmaZero[ring]++;
        if (*length>MT_RX_BUF_SIZE) rxDmaOversize[ring]++;
        if (!(ctrl & MT_DMA_CTL_LAST_SEC0)) rxDmaFragment[ring]++;
        if (*length>=4 && *length<=MT_RX_BUF_SIZE && (ctrl & MT_DMA_CTL_LAST_SEC0)) {
            const uint32_t d0=le32(*data),type=d0>>27,flag=(d0>>16)&15;
            if (type==2 || type==8 || (type==7 && flag==1)) rxDmaFrames[ring]++;
        }
    }
    if (*length>MT_RX_BUF_SIZE || !(ctrl & MT_DMA_CTL_LAST_SEC0)) *length=0;
    return true;
}
void itlmt7922::ringRelease(itl_ring &r,int bi)
{
    if (!r.n || bi<0 || bi>=r.n) return;
    uint8_t *d=r.desc.va+r.head*16;
    put32(d,(uint32_t)(r.buf.pa+(uint64_t)bi*MT_RX_BUF_SIZE));
    put32(d+8,0); put32(d+12,0); put32(d+4,MT_DMA_CTL_SD_LEN0(MT_RX_BUF_SIZE));
    r.slotBuf[r.head]=(uint16_t)bi; r.head=(r.head+1)%r.n; r.tail=(r.tail+1)%r.n;
    barrier(); wr(r.regs+Q_CPU_IDX,(uint32_t)r.head);
}
void itlmt7922::m2State(const char *tag)
{
    m2log("%s LP=%08x MISC=%08x GLO=%08x RX0=%u RX4=%u RXdata=%u",tag,
          rdA(MT_CONN_ON_LPCTL),rdA(MT_CONN_ON_MISC),rdA(MT_WFDMA0_GLO_CFG),
          rxEvt.n?rd(rxEvt.regs+Q_DMA_IDX):0,rxWa.n?rd(rxWa.regs+Q_DMA_IDX):0,
          rxData.n?rd(rxData.regs+Q_DMA_IDX):0);
}
int itlmt7922::uniSend(uint8_t cid,const void *payload,size_t plen,bool query,
                      uint8_t *out,size_t max,uint32_t *length,uint32_t timeout)
{
    int status=0;
    return mcuSend(kUni | cid | (query?kQuery:0),payload,plen,true,&status,out,max,length,timeout);
}
void itlmt7922::handleRxPacket(const uint8_t *p,uint32_t length)
{
    if (length<4) return;
    const uint32_t d0=le32(p),type=d0>>27,flag=(d0>>16)&15;
    if (type==6) { m3TxFree(p,length); return; }
    if (type==2 || type==8 || (type==7 && flag==1)) {
        rxPkts++;
        rxParseFrame(p,length);
        return;
    }
    if (type!=7 || length<36) return;
    evCount++;
    const bool uniUnsol=(p[30]&4)!=0;
    if ((!uniUnsol && p[28]==0xf0) || (uniUnsol && p[28]==0x0a)) {
        firmwareFault=true; recoverWanted=true; m3lost=true;
        strlcpy(m3lostWhy,"firmware coredump",sizeof(m3lostWhy));
        m2log("firmware coredump eid=%02x namespace=%u",p[28],uniUnsol?1:0);
        return;
    }
    if (!uniUnsol && p[28]==0x0d && length>=52 && p[36]==scanSeq) {
        scanDone=true;
        m2log("scan_done seq=%u channels=%u state=%u",p[36],p[40],p[41]);
    }
    m3Event(p,length);
}
void itlmt7922::rxDataPoll()
{
    // Loop-entry gap while associated. MCU waits also drain the RX rings
    // directly, so this is not a claim that DMA went unserviced throughout.
    const uint32_t now=nowMs();
    if (m3linkUp) {
        if (rxDmaLastPollMs) {
            const uint32_t gap=now-rxDmaLastPollMs;
            if (gap>rxDmaMaxGapMs) rxDmaMaxGapMs=gap;
        }
        rxDmaLastPollMs=now;
    } else rxDmaLastPollMs=0;
    itl_ring *rings[]={&rxEvt,&rxWa,&rxData};
    for (unsigned q=0;q<3;q++) {
        const uint8_t *p; uint32_t length; int bi;
        unsigned consumed=0;
        for (;consumed<128 && !shouldStop() && ringPeek(*rings[q],&p,&length,&bi);consumed++) {
            handleRxPacket(p,length); ringRelease(*rings[q],bi);
            if (firmwareFault) break;
        }
        // Inspect the next descriptor without another ringPeek(), which would
        // count it twice before consumption on the following pass.
        const itl_ring &r=*rings[q];
        if (consumed==128 && r.n && r.desc.va && r.tail!=r.head &&
            (le32(r.desc.va+r.tail*16+4)&MT_DMA_CTL_DMA_DONE)) rxDmaBudget[q]++;
    }
    ethFlush();
}
void itlmt7922::rxFrameDump(const uint8_t *p,uint32_t length)
{
    if (rxDump>=3 || length<24) return;
    rxDump++;
    m2log("RX len=%u d0=%08x d1=%08x d2=%08x",length,le32(p),le32(p+4),le32(p+8));
}
void itlmt7922::rxParseFrame(const uint8_t *p,uint32_t length)
{
    if (m3wantFc && m3RxMgmt(p,length)) return;
    if (m3dataOn && m3RxCtl(p,length)) return;
    if (m3dataOn && m3RxData(p,length)) return;
    Mt7922RxView view={};
    if (mt7922_parse_rx_normal(p,length,&view)!=MT7922_RX_OK) { rxOther++; return; }
    const uint8_t *f=p+view.frame_offset;
    const uint32_t n=view.frame_length;
    if ((m3linkUp || m3wantEapol) && n>=26 &&
        ((f[0]&0xfc)==0xc0 || (f[0]&0xfc)==0xa0) &&
        !memcmp(f+10,tgtBssid,6) && !memcmp(f+16,tgtBssid,6) &&
        (!memcmp(f+4,mac,6) || (f[4]&1))) {
        uint16_t reason=le16(f+24);
        if (m3wantEapol) { m3hsApLeave=true; m3hsApReason=reason; }
        else { m3lost=true; snprintf(m3lostWhy,sizeof(m3lostWhy),"AP disconnect reason %u",reason); }
        return;
    }
    Mt7922Beacon beacon={};
    if (!mt7922_parse_beacon(f,n,&beacon)) { rxOther++; return; }
    char ssid[33]={}; memcpy(ssid,beacon.ssid,beacon.ssid_length);
    const uint8_t channel=beacon.channel?beacon.channel:view.channel;
    rxBeacons++;
    if (channel<sizeof(chHist) && chHist[channel]!=255) chHist[channel]++;
    m3Capture(f,n,ssid,channel);
    apSeen(p,view.packet_length,view.frame_offset,ssid,channel);
}
int itlmt7922::m2Scan(const char *ssid)
{
    int rc = m2ScanPass(ssid, 0);
    if (rc) return rc;
    if (shouldStop()) return -125;
    if (firmwareFault) return -5;
    if (ssid) return 0;                                  // a directed scan only needs the primary list
    int rcDfs = m2ScanPass(nullptr, 1);                   // optional passive DFS pass
    if (shouldStop()) return -125;
    if (firmwareFault) return -5;
    // Some firmware/domain combinations reject DFS or never complete that
    // pass. Keep the successful primary scan usable instead of aborting M2.
    if (rcDfs) m2log("optional DFS scan rc=%d; keeping primary results", rcDfs);
    return 0;
}

int itlmt7922::m2ScanPass(const char *ssid, int part)
{
    if (shouldStop() || firmwareFault) return -5;
    const size_t sl=ssid?strnlen(ssid,33):0;
    if (sl>32 || (part && sl)) return -22;
    const uint8_t (*list)[2] = part ? chansDfs : chans;
    const unsigned count = part ? (unsigned)(sizeof(chansDfs)/sizeof(chansDfs[0]))
                                : (unsigned)(sizeof(chans)/sizeof(chans[0]));
    uint8_t scan[1186]={};
    scanSeq=(uint8_t)((scanSeq+1)&0x7f); if (!scanSeq) scanSeq=1;
    scan[0]=scanSeq; scan[2]=sl?1:0; scan[3]=sl?4:1;
    scan[4]=sl?1:0; scan[5]=sl?2:0; scan[6]=1u<<5; scan[7]=1;
    if (sl) { put32(scan+8,(uint32_t)sl); memcpy(scan+12,ssid,sl); scan[1185]=1; }
    put16(scan+154,120); put16(scan+156,120*(uint16_t)count);
    scan[158]=4; scan[159]=(uint8_t)count;
    memcpy(scan+160,list,count*2); put16(scan+828,60); memset(scan+1110,255,6);
    scanDone=false; bzero(chHist,sizeof(chHist));
    int rc=mcuSend(kCe|3,scan,sizeof(scan),false,nullptr);
    m2log("CE scan submit rc=%d seq=%u directed=%u",rc,scanSeq,sl?1:0);
    if (rc) return rc;
    const uint32_t start=nowMs();
    uint32_t publish=start;
    while (!shouldStop() && !firmwareFault && !scanDone && (uint32_t)(nowMs()-start)<20000) {
        rxDataPoll();
        if ((uint32_t)(nowMs()-publish)>=1000) { m2Publish(); publish=nowMs(); }
        IOSleep(1);
    }
    scanMs=nowMs()-start;
    if (!scanDone && !shouldStop() && !firmwareFault) {
        uint8_t cancel[4]={scanSeq,0,0,0};
        mcuSend(kCe|0x1b,cancel,4,false,nullptr);
    }
    if (scanDone) for (unsigned i=0;i<300 && !shouldStop() && !firmwareFault;i++) { rxDataPoll(); IOSleep(1); }
    m2Publish();
    m2log("CE scan done=%u ms=%u aps=%d rx=%u bcn=%u",scanDone?1:0,scanMs,nAps,rxPkts,rxBeacons);
    return shouldStop()?-125:firmwareFault?-5:scanDone?0:-110;
}
int itlmt7922::m2Run()
{
    uint8_t event[2048]={}; uint32_t length=0; int status=0;
    int rc=mcuSend(kCe|0x8a,nullptr,0,true,&status,event,sizeof(event),&length,5000);
    if (rc || length<40) { m2log("NIC capability rc=%d len=%u",rc,length); return rc?rc:-22; }
    uint16_t count=le16(event+36); size_t offset=40; bool got=false;
    if (!count || count>(length-offset)/8) return -22;
    for (uint16_t i=0;i<count;i++) {
        if (offset>length || length-offset<8) return -22;
        uint32_t tag=le32(event+offset),n=le32(event+offset+4); offset+=8;
        if (n>length-offset) return -22;
        if (tag==7) {
            if (got || n<6 || (event[offset]&1) ||
                !(event[offset]|event[offset+1]|event[offset+2]|event[offset+3]|event[offset+4]|event[offset+5])) return -22;
            memcpy(mac,event+offset,6); got=true;
        }
        offset+=n;
    }
    if (!got || length-offset>3) { m2log("NIC cap missing MAC or trailing bytes=%lu",(unsigned long)(length-offset)); return -22; }
    while (offset<length) if (event[offset++]) return -22;
    if (nativeMode) mac[0]|=2;
    setProperty("IOMACAddress",mac,6); setProperty("itlmt_mac_source","firmware");
    m2log("MAC=%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    publishService();
    rc=m3HwPrep(); if (rc) return rc;
    uint8_t dev[16]={}; put16(dev+4,0); put16(dev+6,12); dev[8]=1; memcpy(dev+10,mac,6);
    rc=uniSend(1,dev,sizeof(dev),false,event,sizeof(event),&length,3000);
    if (rc) return rc;
    uint8_t bss[36]={}; uint8_t *b=bss+4;
    put16(b+2,32); b[4]=1; put32(b+8,0x10001); b[12]=1; put16(b+20,19); put16(b+26,19);
    rc=uniSend(2,bss,sizeof(bss),false,event,sizeof(event),&length,3000);
    if (rc) return rc;
    return m2Scan(nullptr);
}
void itlmt7922::m2log(const char *fmt, ...)
{
    char tmp[320];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    IOLog("itlmt7922: M2 %s\n", tmp);
    size_t n = strlen(tmp);
    if (m2len + n + 2 < sizeof(m2buf)) {
        memcpy(m2buf + m2len, tmp, n);
        m2len += n;
        m2buf[m2len++] = ';';
        m2buf[m2len] = 0;
    }
    setProperty("m2-log", m2buf);
}

void itlmt7922::m2Publish()
{
    size_t n = 0;
    m2res[0] = 0;
    n += (size_t)snprintf(m2res + n, sizeof(m2res) - n, "rx=%u bcn=%u oth=%u ap=%d sd=%d@%ums h:", rxPkts, rxBeacons, rxOther, nAps,
                  scanDone ? 1 : 0, scanMs);
    for (unsigned c = 0; c < sizeof(chHist) && n + 12 < sizeof(m2res); c++)
        if (chHist[c]) n += (size_t)snprintf(m2res + n, sizeof(m2res) - n, "%u=%u,", c, chHist[c]);
    n += (size_t)snprintf(m2res + n, sizeof(m2res) - n, ":");
    for (int i = 0; i < nAps && n + 40 < sizeof(m2res); i++)
        n += (size_t)snprintf(m2res + n, sizeof(m2res) - n, " %s/%u/%02x%02x", aps[i].ssid, aps[i].ch, aps[i].bssid[4],
                      aps[i].bssid[5]);
    setProperty("m2-res", m2res);
}
