#define _CRT_SECURE_NO_WARNINGS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;


class PcodeArchitecture : public Architecture {
	size_t m_bits;
	BNEndianness m_endian;

public:
	PcodeArchitecture(const std::string& name, BNEndianness endian, size_t bits): Architecture(name), m_bits(bits), m_endian(endian) {
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
        Architecture* arch = new PcodeArchitecture("pcode_v850", LittleEndian, 32);
        Architecture::Register(arch);
        // BinaryViewType::RegisterArchitecture("ELF", 0x08, BigEndian, v850);
        return true;
    }
}
