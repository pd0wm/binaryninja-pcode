#define _CRT_SECURE_NO_WARNINGS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <cassert>

#include "third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.hh"
#include "third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/loadimage.hh"

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;

// https://github.com/angr/pypcode/blob/master/pypcode/native/csleigh.cc
class SimpleLoadImage : public LoadImage
{
    uintb                m_baseaddr;
    int4                 m_length;
    const unsigned char *m_data;

public:
    SimpleLoadImage()
    : LoadImage("nofile")
    {
        m_baseaddr = 0;
        m_data = NULL;
        m_length = 0;
    }

    void setData(uintb ad, const unsigned char *ptr,int4 sz)
    {
        m_baseaddr = ad;
        m_data = ptr;
        m_length = sz;
    }

    void loadFill(uint1 *ptr, int4 size, const Address &addr)
    {
        uintb start = addr.getOffset();
        uintb max = m_baseaddr + m_length - 1;

        //
        // When decoding an instruction, SLEIGH will attempt to pull in several
        // bytes at a time, starting at each instruction boundary.
        //
        // If the start address is outside of the defined range, bail out.
        // Otherwise, if we have some data to provide but cannot sastisfy the
        // entire request, fill the remainder of the buffer with zero.
        //
        if (start > max || start < m_baseaddr) {
            throw std::out_of_range("Attempting to lift outside buffer range");
        }

        for(int4 i = 0; i < size; i++) {
            uintb curoff = start + i;
            if ((curoff < m_baseaddr) || (curoff>max)) {
                ptr[i] = 0;
                continue;
            }
            uintb diff = curoff - m_baseaddr;
            ptr[i] = m_data[(int4)diff];
        }
    }

    virtual string getArchType(void) const { return "myload"; }
    virtual void adjustVma(long adjust) { }
};


class PcodeArchitecture : public Architecture {
	size_t m_bits;
	BNEndianness m_endian;

    // ghidra storage
    SimpleLoadImage     m_loader;
    ContextInternal     m_context_internal;
    DocumentStorage     m_document_storage;
    Document           *m_document;
    Element            *m_tags;
    std::unique_ptr<Sleigh>  m_sleigh;

public:
	PcodeArchitecture(const std::string& name, BNEndianness endian, size_t bits): Architecture("pcode_" + name), m_bits(bits), m_endian(endian) {
        // TODO: embed sla files inside plugin .so
        const std::string path = "/home/willem/Development/binaryninja-pcode/build/out/sla/" + name + ".sla";

        LogInfo("Opening sla: %s", path.c_str());
        m_document = m_document_storage.openDocument(path);
        try {
            m_document = m_document_storage.openDocument(path);
            m_tags = m_document->getRoot();
            m_document_storage.registerTag(m_tags);
        } catch (...) {
            LogError("Error opening %s", path.c_str());
            throw;
        }

        m_sleigh.reset(new Sleigh(&m_loader, &m_context_internal));
        m_sleigh->initialize(m_document_storage);


        LogInfo("Done loading: %s", path.c_str());
	}

    BNEndianness GetEndianness() const override {
        return m_endian;
    }

    size_t GetAddressSize() const override {
        return m_bits / 8;
    }

    bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override {
        return false;
    }

    bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) override {
        return false;
    }


};


extern "C"
{
    BN_DECLARE_CORE_ABI_VERSION


    BINARYNINJAPLUGIN bool CorePluginInit() {
        try {
            Architecture* arch = new PcodeArchitecture("V850", LittleEndian, 32);
            Architecture::Register(arch);

            // BinaryViewType::RegisterArchitecture("ELF", 0x08, BigEndian, v850);
            return true;
        } catch (...) {
            return false;
        }
    }
}
