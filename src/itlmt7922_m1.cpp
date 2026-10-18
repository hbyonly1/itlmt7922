// SPDX-License-Identifier: BSD-3-Clause-Clear
// MT7922 PCIe bootstrap adapted from Linux mt76, Copyright (C) MediaTek Inc.
// References: mt7921/pci.c, pci_mcu.c; mt792x_dma.c; mt76_connac_mcu.c.
#include "itlmt7922.hpp"
#include "mt7922_regs.h"
#include <string.h>
#include <libkern/libkern.h>

extern "C" {
extern const uint8_t itl_fw_patch[], itl_fw_patch_end[];
extern const uint8_t itl_fw_ram[], itl_fw_ram_end[];
}

static const int kIo = -5, kInvalid = -22, kTimeout = -110, kStopped = -125;
static inline uint32_t le32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static inline uint32_t be32(const uint8_t *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }
static inline void put32(uint8_t *p,uint32_t v) { memcpy(p,&v,4); }
static inline void put16(uint8_t *p,uint16_t v) { memcpy(p,&v,2); }
static inline void barrier() { __sync_synchronize(); }


void itlmt7922::m1log(const char *fmt, ...)
{
    char tmp[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    IOLog("itlmt7922: M1 %s\n", tmp);
    size_t n = strlen(tmp);
    if (n + 2 < sizeof(m1buf)) {
        // Ring: the old append-only buffer stopped at full, which hid the last MCU commands of a failing connect.
        while (m1len + n + 2 >= sizeof(m1buf)) {
            char *sep = (char *)memchr(m1buf, ';', m1len);
            size_t cut = sep ? (size_t)(sep - m1buf) + 1 : m1len;
            memmove(m1buf, m1buf + cut, m1len - cut);
            m1len -= cut;
            m1buf[m1len] = 0;
        }
        memcpy(m1buf + m1len, tmp, n);
        m1len += n;
        m1buf[m1len++] = ';';
        m1buf[m1len] = 0;
    }
    setProperty("m1-log", m1buf);
}

uint32_t itlmt7922::mapAddr(uint32_t addr,uint32_t *restore)
{
    *restore=0xffffffffu;
    if (addr < MT_BAR0_DIRECT_LIMIT) return addr;
    for (size_t i=0;i<ITL_FIXED_MAP_N;i++) {
        if (addr >= itl_fixed_map[i].phys && addr-itl_fixed_map[i].phys < itl_fixed_map[i].size)
            return itl_fixed_map[i].maps+addr-itl_fixed_map[i].phys;
    }
    if ((addr>=0x18000000u && addr<0x18c00000u) || (addr>=0x70000000u && addr<0x78000000u) ||
        (addr>=0x7c000000u && addr<0x7c400000u)) {
        uint32_t old=rd(MT_HIF_REMAP_L1);
        if (old==0xffffffffu) return 0xffffffffu;
        wr(MT_HIF_REMAP_L1,(old & ~MT_HIF_REMAP_L1_MASK) | (addr>>16));
        (void)rd(MT_HIF_REMAP_L1);
        *restore=old;
        return MT_HIF_REMAP_BASE_L1+(addr & 0xffffu);
    }
    return 0xffffffffu;
}

uint32_t itlmt7922::rdA(uint32_t addr)
{
    uint32_t old,off=mapAddr(addr,&old);
    if (off==0xffffffffu) return off;
    uint32_t value=rd(off);
    if (old!=0xffffffffu) { wr(MT_HIF_REMAP_L1,old); (void)rd(MT_HIF_REMAP_L1); }
    return value;
}

void itlmt7922::wrA(uint32_t addr,uint32_t value)
{
    uint32_t old,off=mapAddr(addr,&old);
    if (off==0xffffffffu) return;
    wr(off,value);
    if (old!=0xffffffffu) { (void)rd(off); wr(MT_HIF_REMAP_L1,old); (void)rd(MT_HIF_REMAP_L1); }
}

void itlmt7922::rmwA(uint32_t addr,uint32_t clear,uint32_t set)
{
    uint32_t value=rdA(addr);
    if (value!=0xffffffffu) wrA(addr,(value & ~clear) | set);
}

bool itlmt7922::pollA(uint32_t addr,uint32_t mask,uint32_t value,uint32_t timeout)
{
    uint32_t start=nowMs();
    do {
        uint32_t actual=rdA(addr);
        if (actual!=0xffffffffu && (actual & mask)==value) return true;
        if (shouldStop()) return false;
        IODelay(100);
    } while ((uint32_t)(nowMs()-start)<timeout);
    return false;
}

bool itlmt7922::driverOwn()
{
    for (int i=0;i<10 && !shouldStop();i++) {
        wrA(MT_CONN_ON_LPCTL,PCIE_LPCR_HOST_CLR_OWN);
        if (pollA(MT_CONN_ON_LPCTL,PCIE_LPCR_HOST_OWN_SYNC,0,50)) return true;
    }
    return false;
}

bool itlmt7922::dmaAlloc(itl_dma_buf &b,size_t size,bool cached)
{
    b.md=IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task,
        kIODirectionInOut | kIOMemoryPhysicallyContiguous | (cached ? 0 : kIOMapInhibitCache),size,0x00000000fffff000ULL);
    if (!b.md) return false;
    b.va=(uint8_t *)b.md->getBytesNoCopy(); b.size=size;
    b.pa=b.md->getPhysicalSegment(0,nullptr,kIOMemoryMapperNone);
    if (!b.va || !b.pa || b.pa>=0x100000000ULL || size>0x100000000ULL-b.pa) { dmaFree(b); return false; }
    bzero(b.va,size);
    return true;
}

void itlmt7922::dmaFree(itl_dma_buf &b)
{
    if (b.md) b.md->release();
    b.md=nullptr; b.va=nullptr; b.pa=0; b.size=0;
}

void itlmt7922::ringFree(itl_ring &r)
{
    dmaFree(r.desc); dmaFree(r.buf); r.n=0; r.head=r.tail=0; r.regs=0;
}

bool itlmt7922::ringInit(itl_ring &r,int qid,uint32_t base,int n,bool rx,bool cached)
{
    if (n<2 || (rx && n>(int)(sizeof(r.slotBuf)/sizeof(r.slotBuf[0])))) return false;
    r.n=n; r.head=r.tail=0; r.regs=base+(uint32_t)qid*0x10u;
    if (!dmaAlloc(r.desc,(size_t)n*16) || !dmaAlloc(r.buf,rx?(size_t)n*MT_RX_BUF_SIZE:(&r==&txData?(size_t)kTxSlots*2048:4096),cached)) return false;
    for (int i=0;i<n;i++) put32(r.desc.va+i*16+4,MT_DMA_CTL_DMA_DONE);
    wr(r.regs+Q_CPU_IDX,0); wr(r.regs+Q_DMA_IDX,0);
    wr(r.regs+Q_RING_SIZE,(uint32_t)n); wr(r.regs+Q_DESC_BASE,(uint32_t)r.desc.pa);
    if (rx) {
        for (int i=0;i<n-1;i++) {
            uint8_t *d=r.desc.va+i*16;
            put32(d,(uint32_t)(r.buf.pa+(uint64_t)i*MT_RX_BUF_SIZE));
            put32(d+4,MT_DMA_CTL_SD_LEN0(MT_RX_BUF_SIZE));
            r.slotBuf[i]=(uint16_t)i;
        }
        r.head=n-1; barrier(); wr(r.regs+Q_CPU_IDX,(uint32_t)r.head);
    }
    return true;
}

void itlmt7922::dmaDisable()
{
    rmwA(MT_WFDMA0_GLO_CFG,GLO_TX_DMA_EN | GLO_RX_DMA_EN | GLO_CSR_DISP_BASE_PTR_CHAIN_EN |
        GLO_OMIT_TX_INFO | GLO_OMIT_RX_INFO | GLO_OMIT_RX_INFO_PFET2,0);
    if (!pollA(MT_WFDMA0_GLO_CFG,GLO_TX_DMA_BUSY | GLO_RX_DMA_BUSY,0,100))
        m1log("DMA busy during disable GLO=%08x",rdA(MT_WFDMA0_GLO_CFG));
    rmwA(MT_WFDMA0_GLO_CFG_EXT0,GLO_EXT0_CSR_TX_DMASHDL_EN,0);
    rmwA(MT_DMASHDL_SW_CONTROL,0,MT_DMASHDL_DMASHDL_BYPASS);
    rmwA(MT_WFDMA0_RST,MT_WFDMA0_RST_DMASHDL_ALL_RST | MT_WFDMA0_RST_LOGIC_RST,0);
    rmwA(MT_WFDMA0_RST,0,MT_WFDMA0_RST_DMASHDL_ALL_RST | MT_WFDMA0_RST_LOGIC_RST);
}

void itlmt7922::dmaEnable()
{
    // mt792x_dma_prefetch() default Connac2 branch. No MT7925-specific setup.
    static const unsigned rxIds[]={0,2,3,4,5};
    for (unsigned i=0;i<5;i++) wrA(MT_WFDMA0_RX_RING_EXT_CTRL(rxIds[i]),((0x40u*i)<<16)|4);
    for (unsigned i=0;i<7;i++) wrA(MT_WFDMA0_TX_RING_EXT_CTRL(i),((0x140u+0x40u*i)<<16)|4);
    wrA(MT_WFDMA0_TX_RING_EXT_CTRL(16),(0x340u<<16)|4);
    wrA(MT_WFDMA0_TX_RING_EXT_CTRL(17),(0x380u<<16)|4);
    wrA(MT_WFDMA0_RST_DTX_PTR,0xffffffffu);
    wrA(MT_WFDMA0_PRI_DLY_INT_CFG0,0);
    rmwA(MT_WFDMA0_GLO_CFG,0,GLO_TX_WB_DDONE | GLO_FIFO_LITTLE_ENDIAN | GLO_CLK_GAT_DIS |
        GLO_OMIT_TX_INFO | GLO_DMA_SIZE_3 | GLO_FIFO_DIS_CHECK | GLO_RX_WB_DDONE |
        GLO_CSR_DISP_BASE_PTR_CHAIN_EN | GLO_OMIT_RX_INFO_PFET2);
    rmwA(MT_WFDMA0_GLO_CFG,0,GLO_TX_DMA_EN | GLO_RX_DMA_EN);
    rmwA(MT_WFDMA_DUMMY_CR,0,MT_WFDMA_NEED_REINIT);
    // DMA and MCU events are polled; host interrupt sources stay masked.
    wrA(MT_WFDMA0_HOST_INT_ENA,0);
    rmwA(MT_MCU2HOST_SW_INT_ENA,0,MT_MCU_CMD_WAKE_RX_PCIE);
}

bool itlmt7922::txKick(itl_ring &r,size_t length)
{
    if (shouldStop() || !r.n || !r.buf.va || length>r.buf.size || length>0x3fff) return false;
    uint8_t *d=r.desc.va+r.head*16;
    put32(d,(uint32_t)r.buf.pa); put32(d+8,0); put32(d+12,0);
    put32(d+4,MT_DMA_CTL_SD_LEN0(length) | MT_DMA_CTL_LAST_SEC0);
    r.head=(r.head+1)%r.n; barrier(); wr(r.regs+Q_CPU_IDX,(uint32_t)r.head);
    uint32_t start=nowMs();
    do {
        if ((rd(r.regs+Q_DMA_IDX)&0xffffu)==(uint32_t)r.head) return true;
        if (shouldStop()) return false;
        IODelay(50);
    } while ((uint32_t)(nowMs()-start)<3000);
    m1log("TX stall regs=%x cpu=%d dma=%u GLO=%08x",r.regs,r.head,rd(r.regs+Q_DMA_IDX),rdA(MT_WFDMA0_GLO_CFG));
    return false;
}

int itlmt7922::mcuSend(uint32_t cmd,const void *payload,size_t length,bool wantResponse,int *result,
    uint8_t *evOut,size_t evMax,uint32_t *evLength,uint32_t timeoutMs)
{
    const bool unified=cmd & MT_MCU_CMD_UNI;
    const size_t header=unified?48:64;
    if (evLength) *evLength=0;
    if (result) *result=0;
    if (length>4096-header || (length && !payload) || !txWm.buf.va) return kInvalid;
    if (shouldStop()) return kStopped;
    if (firmwareFault) return kIo;
    uint8_t seq=++mcuSeq & 15;
    if (!seq) seq=++mcuSeq & 15;
    uint8_t *p=txWm.buf.va; bzero(p,header);
    uint32_t total=(uint32_t)(header+length);
    put32(p,total | (2u<<23) | (0x20u<<25));
    put32(p+4,(1u<<31) | (1u<<16)); // Connac2 LONG_FORMAT and HDR_FORMAT=CMD.
    put16(p+32,(uint16_t)(total-32));
    if (unified) {
        put16(p+34,(uint16_t)(cmd & 0xff)); p[37]=MCU_PKT_ID; p[39]=seq;
        p[42]=(cmd & MT_MCU_CMD_WA)?2:0;
        p[43]=(cmd & MT_MCU_CMD_QUERY)?3:7;
    } else {
        put16(p+34,0x8000); p[36]=(uint8_t)cmd; p[37]=MCU_PKT_ID; p[39]=seq;
        uint8_t ext=(uint8_t)(cmd>>8);
        p[41]=ext; p[42]=(cmd & MT_MCU_CMD_WA)?2:0; p[43]=ext?1:0;
        p[38]=(ext || (cmd & MT_MCU_CMD_CE)) ? ((cmd & MT_MCU_CMD_QUERY)?MCU_Q_QUERY:MCU_Q_SET) : MCU_Q_NA;
    }
    if (length) memcpy(p+header,payload,length);
    if (!txKick(txWm,total)) return shouldStop()?kStopped:kTimeout;
    if (!wantResponse) return 0;
    uint32_t start=nowMs();
    do {
        itl_ring *events[]={&rxEvt,&rxWa};
        for (unsigned q=0;q<2;q++) {
            const uint8_t *ev; uint32_t n; int bi;
            for (unsigned budget=0;budget<64 && ringPeek(*events[q],&ev,&n,&bi);budget++) {
                uint32_t type=n>=4?le32(ev)>>27:0xffffffffu;
                uint32_t flag=n>=4?(le32(ev)>>16)&15u:0;
                bool frame=type==2 || type==8 || (type==7 && flag==1);
                bool match=type==7 && !frame && n>=MCU_RX_HEADER_SIZE && !(ev[30]&4u) && ev[29]==seq;
                if (match && unified)
                    match=n>=44 && ev[28]==1 && ev[36]==(uint8_t)cmd;
                handleRxPacket(ev,n);
                if (firmwareFault) { ringRelease(*events[q],bi); return kIo; }
                if (match) {
                    int responseStatus=0;
                    m1log("MCU cid=%02x seq=%u eid=%02x len=%u ring=%u",(unsigned)(cmd&255),seq,ev[28],n,q?4:0);
                    if (result && ((cmd&0xff)==MCU_CMD_PATCH_SEM_CONTROL || (cmd&0xff)==MCU_CMD_PATCH_FINISH_REQ))
                        *result=n>32?ev[32]:-1;
                    else if (unified) {
                        responseStatus=(int)le32(ev+40);
                        if (result) *result=responseStatus;
                    }
                    if (evOut && evMax) { size_t copy=n<evMax?n:evMax; memcpy(evOut,ev,copy); if (evLength) *evLength=(uint32_t)copy; }
                    ringRelease(*events[q],bi);
                    return responseStatus;
                }
                ringRelease(*events[q],bi);
                if (shouldStop()) return kStopped;
            }
        }
        const uint8_t *packet; uint32_t n; int bi;
        for (unsigned budget=0;budget<64 && ringPeek(rxData,&packet,&n,&bi);budget++) {
            handleRxPacket(packet,n); ringRelease(rxData,bi); if (shouldStop()) return kStopped;
        }
        if (shouldStop()) return kStopped;
        IODelay(50);
    } while ((uint32_t)(nowMs()-start)<timeoutMs);
    m1log("MCU timeout cid=%02x seq=%u rx0 dma=%u rx4 dma=%u LP=%08x",(unsigned)(cmd&255),seq,
        rd(rxEvt.regs+Q_DMA_IDX),rd(rxWa.regs+Q_DMA_IDX),rdA(MT_CONN_ON_LPCTL));
    return kTimeout;
}

int itlmt7922::fwScatter(const uint8_t *data,size_t length)
{
    while (length) {
        size_t n=length>4096?4096:length; memcpy(txFwdl.buf.va,data,n);
        if (!txKick(txFwdl,n)) return shouldStop()?kStopped:kTimeout;
        data+=n; length-=n;
    }
    return 0;
}

int itlmt7922::initDownload(uint32_t addr,uint32_t length,uint32_t mode)
{
    uint8_t request[12]; put32(request,addr); put32(request+4,length); put32(request+8,mode);
    // Same address-dependent opcode selection as mt76_connac_mcu_init_download.
    bool patchCommand=(addr==0x200000u || addr==0x900000u);
    return mcuSend(patchCommand?MCU_CMD_PATCH_START_REQ:MCU_CMD_TARGET_ADDRESS_LEN_REQ,request,sizeof(request),true,nullptr);
}

int itlmt7922::loadPatch()
{
    const uint8_t *fw=itl_fw_patch; size_t size=(size_t)(itl_fw_patch_end-itl_fw_patch);
    if (size<PATCH_HDR_SIZE) return kInvalid;
    uint32_t regions=be32(fw+44);
    if (!regions || regions>(size-PATCH_HDR_SIZE)/PATCH_SEC_SIZE) return kInvalid;
    m1log("patch built=%.16s size=%lu regions=%u",(const char *)fw,(unsigned long)size,regions);
    uint8_t op[4]; put32(op,PATCH_SEM_GET); int sem=-1;
    int rc=mcuSend(MCU_CMD_PATCH_SEM_CONTROL,op,4,true,&sem);
    if (rc) return rc;
    m1log("patch semaphore=%d",sem);
    if (sem==PATCH_IS_DL) return 0;
    if (sem!=PATCH_NOT_DL_SEM_SUCCESS) return kIo;
    for (uint32_t i=0;i<regions && !rc;i++) {
        const uint8_t *sec=fw+PATCH_HDR_SIZE+(size_t)i*PATCH_SEC_SIZE;
        uint32_t offset=be32(sec+4),addr=be32(sec+12),length=be32(sec+16),info=be32(sec+20);
        if ((be32(sec)&PATCH_SEC_TYPE_MASK)!=PATCH_SEC_TYPE_INFO || offset>size || length>size-offset) { rc=kInvalid; break; }
        uint32_t mode=DL_MODE_NEED_RSP;
        if (info!=PATCH_SEC_NOT_SUPPORT) {
            switch (info>>24) {
            case 0: break;
            case 1: mode|=DL_MODE_ENCRYPT | ((info&3)<<1) | DL_MODE_RESET_SEC_IV; break;
            case 2: mode|=DL_MODE_ENCRYPT | DL_CONFIG_ENCRY_MODE_SEL | DL_MODE_RESET_SEC_IV; break;
            default: rc=kInvalid; break;
            }
        }
        if (rc) break;
        m1log("patch region=%u addr=%08x length=%u mode=%08x",i,addr,length,mode);
        rc=initDownload(addr,length,mode);
        if (!rc) rc=fwScatter(fw+offset,length);
    }
    if (!rc) {
        uint8_t finish[4]={}; int status=-1;
        rc=mcuSend(MCU_CMD_PATCH_FINISH_REQ,finish,4,true,&status);
        if (!rc && status) rc=kIo;
        m1log("patch finish rc=%d status=%d",rc,status);
    }
    put32(op,PATCH_SEM_RELEASE); int released=-1;
    int releaseRc=mcuSend(MCU_CMD_PATCH_SEM_CONTROL,op,4,true,&released);
    if (!rc && (releaseRc || released!=PATCH_REL_SEM_SUCCESS)) rc=releaseRc?releaseRc:kIo;
    return rc;
}

int itlmt7922::loadRam()
{
    const uint8_t *fw=itl_fw_ram; size_t size=(size_t)(itl_fw_ram_end-itl_fw_ram);
    if (size<FW_TRAILER_SIZE) return kInvalid;
    const uint8_t *trailer=fw+size-FW_TRAILER_SIZE;
    uint32_t regions=trailer[2];
    if (!regions || regions>(size-FW_TRAILER_SIZE)/FW_REGION_SIZE) return kInvalid;
    size_t dataSize=size-FW_TRAILER_SIZE-(size_t)regions*FW_REGION_SIZE,offset=0;
    uint32_t override=0;
    m1log("RAM version=%.10s built=%.15s regions=%u size=%lu",(const char *)trailer+7,(const char *)trailer+17,
        regions,(unsigned long)size);
    for (uint32_t i=0;i<regions;i++) {
        const uint8_t *region=trailer-(size_t)(regions-i)*FW_REGION_SIZE;
        uint32_t addr=le32(region+16),length=le32(region+20); uint8_t feature=region[24];
        if (offset>dataSize || length>dataSize-offset) return kInvalid;
        if (!(feature & FW_FEATURE_NON_DL)) {
            uint32_t mode=DL_MODE_NEED_RSP | (feature&6);
            if (feature & FW_FEATURE_SET_ENCRYPT) mode|=DL_MODE_ENCRYPT | DL_MODE_RESET_SEC_IV;
            if (feature & FW_FEATURE_ENCRY_MODE) mode|=DL_CONFIG_ENCRY_MODE_SEL;
            if (feature & FW_FEATURE_OVERRIDE_ADDR) override=addr;
            m1log("RAM region=%u addr=%08x length=%u mode=%08x",i,addr,length,mode);
            int rc=initDownload(addr,length,mode);
            if (!rc) rc=fwScatter(fw+offset,length);
            if (rc) return rc;
        }
        offset+=length;
    }
    uint8_t request[8]; put32(request,override?FW_START_OVERRIDE:0); put32(request+4,override);
    return mcuSend(MCU_CMD_FW_START_REQ,request,8,true,nullptr);
}

int itlmt7922::m1Run()
{
    if (shouldStop()) return kStopped;
    firmwareFault=false;
    if ((rdA(MT_HW_CHIPID)&0xffff)!=0x7922) return kIo;
    pci->setBusMasterEnable(true); busMasterOn=true;
    m1log("stage1 bus master enabled");
    rmwA(MT_WFSYS_SW_RST_B,WFSYS_SW_RST_B,0); IOSleep(50);
    if (shouldStop()) return kStopped;
    rmwA(MT_WFSYS_SW_RST_B,0,WFSYS_SW_RST_B);
    if (!pollA(MT_WFSYS_SW_RST_B,WFSYS_SW_INIT_DONE,WFSYS_SW_INIT_DONE,500)) { m1log("reset timeout"); return kTimeout; }
    m1log("stage2 WFSYS reset done");
    wrA(MT_WFDMA0_HOST_INT_ENA,0); wrA(MT_PCIE_MAC_INT_ENABLE,0xff);
    dmaDisable();
    if ((rdA(MT_WFDMA0_GLO_CFG)&(GLO_TX_DMA_BUSY|GLO_RX_DMA_BUSY))!=0) return kTimeout;
    m1log("stage3 DMA disabled");
    if (!ringInit(txWm,17,MT_TX_RING_BASE,256,false) || !ringInit(txFwdl,16,MT_TX_RING_BASE,128,false) ||
        !ringInit(rxEvt,0,MT_RX_EVENT_RING_BASE,8,true) || !ringInit(rxWa,0,MT_RX_EVENT_RUNTIME_RING_BASE,512,true) ||
        (m3On && !ringInit(txData,MT7922_TXQ_BAND0,MT_TX_RING_BASE,2048,false,true))) { m1log("DMA allocation failed"); return kIo; }
    if (m2On) {
        static const int sizes[]={1536,512,256};
        bool allocated=false;
        for (unsigned i=0;i<3 && !allocated;i++) {
            allocated=ringInit(rxData,0,MT_RX_DATA_RING_BASE,sizes[i],true,true);
            if (!allocated) ringFree(rxData);
        }
        if (!allocated) { m1log("RX data allocation failed"); return kIo; }
    }
    m1log("stage4 rings TX17=%llx TX16=%llx RX0=%llx RX4=%llx RX2=%llx",
        (unsigned long long)txWm.desc.pa,(unsigned long long)txFwdl.desc.pa,(unsigned long long)rxEvt.desc.pa,
        (unsigned long long)rxWa.desc.pa,(unsigned long long)rxData.desc.pa);
    dmaEnable();
    m1log("stage5 DMA enabled GLO=%08x",rdA(MT_WFDMA0_GLO_CFG));
    wrA(MT_SWDEF_MODE,MT_SWDEF_NORMAL_MODE); // __mt7921_init_hardware().
    // mt7921e_mcu_init uses the TOP ownership register after WFSYS reset.
    wrA(MT_TOP_LPCR_HOST_BAND0,MT_TOP_LPCR_HOST_DRV_OWN);
    if (!pollA(MT_TOP_LPCR_HOST_BAND0,MT_TOP_LPCR_HOST_FW_OWN,0,500)) { m1log("TOP driver own timeout"); return kTimeout; }
    rmwA(MT_PCIE_MAC_PM,0,MT_PCIE_MAC_PM_L0S_DIS);
    uint8_t power[4]={1,0,0,0};
    int rc=mcuSend(MCU_CMD_NIC_POWER_CTRL,power,4,false,nullptr);
    if (rc) return rc;
    if (!pollA(MT_CONN_ON_MISC,MT_TOP_MISC_FW_STATE_MASK,MT_TOP_MISC2_FW_PWR_ON,1000)) {
        m1log("firmware-download-ready state missing MISC=%08x",rdA(MT_CONN_ON_MISC));
        return kTimeout;
    }
    m1log("stage6 loading MT7922 patch");
    rc=loadPatch(); m1log("stage7 patch rc=%d",rc); if (rc) return rc;
    rc=loadRam(); m1log("stage8 RAM rc=%d",rc); if (rc) return rc;
    if (!pollA(MT_CONN_ON_MISC,MT_TOP_MISC2_FW_N9_RDY,MT_TOP_MISC2_FW_N9_RDY,1500)) { m1log("firmware ready timeout MISC=%08x",rdA(MT_CONN_ON_MISC)); return kTimeout; }
    m1log("stage9 FIRMWARE READY MISC=%08x",rdA(MT_CONN_ON_MISC));
    setProperty("firmware-ready",kOSBooleanTrue);
    return 0;
}

void itlmt7922::m1Main()
{
    uint32_t delay = 0;
    m2On=diagnosticStage>=2; m3On=diagnosticStage>=3;
    PE_parse_boot_argn("mt7922_delay", &delay, sizeof(delay));
    if (delay>120) delay=120;
    if (nativeMode && diagnosticStage>=3) {
        m3On = m2On = true;
        m1log("native datapath radio engine enabled; legacy Ethernet disabled");
    }
    uint32_t reo = 0;
    if (PE_parse_boot_argn("mt7922_reo", &reo, sizeof(reo)) && reo >= 5 && reo <= 500) reoMs = reo;
    uint32_t no160Arg = 0;
    if (PE_parse_boot_argn("mt7922_no160", &no160Arg, sizeof(no160Arg)) && no160Arg) this->no160 = true;
    uint32_t nopwr = 0, statS = 0;
    if (PE_parse_boot_argn("mt7922_nopwr", &nopwr, sizeof(nopwr)) && nopwr) noPwr = true;
    uint32_t amsduOn = 0;
    if (PE_parse_boot_argn("mt7922_amsdu", &amsduOn, sizeof(amsduOn)) && amsduOn) noAmsdu = false;
    if (PE_parse_boot_argn("mt7922_stat", &statS, sizeof(statS)) && statS >= 1 && statS <= 60) statSecs = statS;
    m3fast=true; fastLevel=3;
    uint32_t fast = 3;
    if (PE_parse_boot_argn("mt7922_fast", &fast, sizeof(fast))) {
        m3fast = fast != 0;
        fastLevel = fast > 5 ? 5 : (uint8_t)fast; // HE level 6 is outside this Connac2 port.
    }
    // Start when the kernel is ready instead of after a fixed sleep: the IOBSD resource is published once the root
    // filesystem is mounted, i.e. early boot (PCI enumeration, the GPU bring-up) is behind us. The firmware is embedded,
    // so nothing else has to exist. mt7922_delay=<s> is an extra delay after that point (0 = none; the old default was 75 s
    // from kext start).
    uint32_t t0 = nowMs();
    OSDictionary *match = IOService::resourceMatching("IOBSD");
    IOService *bsd=nullptr;
    while (match && !bsd && !shouldStop() && (uint32_t)(nowMs()-t0)<120000)
        bsd=IOService::waitForMatchingService(match,1000ull*1000*1000);
    if (match) match->release();
    if (bsd) bsd->release();
    m1log("armed: system ready after %ums (%s), extra delay %us", nowMs() - t0, bsd ? "IOBSD" : "IOBSD wait timed out", delay);
    for (uint32_t elapsed=0;elapsed<delay*10 && !shouldStop();elapsed++) IOSleep(100);
    if (shouldStop()) return;
    int rc = m1Run();
    if (firmwareFault && rc==0) rc=kIo;
    setProperty("firmware-result",(uint32_t)rc,32);
    if (rc) setProperty("wifi-state","firmware-failed");
    else if (!m2On) setProperty("wifi-state","firmware-ready");
    m1log("RESULT rc=%d", rc);
    char s[48];
    snprintf(s, sizeof(s), "M1 rc=%d", rc);
    nvramLog(s);
    if (rc != 0) publishService();                           // no firmware: the (radio-less) interface still has to exist
    if (rc == 0 && m2On && !shouldStop()) {
        int r2 = m2Run();
        setProperty("scan-result",(uint32_t)r2,32);
        if (r2) {
            setProperty("wifi-state", "initialization-failed");
            setProperty("wifi-error", "firmware interface setup or initial scan failed; see m2-log");
        } else if (!m3On) setProperty("wifi-state", "scan-complete");
        m2log("RESULT rc=%d", r2);
        snprintf(s, sizeof(s), "M1 rc=0 M2 rc=%d", r2);
        nvramLog(s);
        publishService();                                    // normally done by m2Run() right after the address is read
        if (r2 == 0 && m3On && !firmwareFault && !shouldStop()) m3Supervise(); // serves connection commands until stopping
    }
    publishService();
}

void itlmt7922::m1Thread(void *arg)
{
    itlmt7922 *self=(itlmt7922 *)arg;
    self->m1Main();
    self->setProperty("dma-quiesced",self->quiesceHardware());
    IOLockLock(self->workerLock);
    self->workerRunning=false;
    IOLockWakeup(self->workerLock,&self->workerRunning,false);
    IOLockUnlock(self->workerLock);
    self->release();
}
