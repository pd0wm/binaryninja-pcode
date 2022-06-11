#define _CRT_SECURE_NO_WARNINGS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <cassert>
#include <mutex>

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

typedef struct {
	OpCode opcode;
	std::optional<VarnodeData> output;
	std::vector<VarnodeData> inputs;
} PcodeOp;

class PcodeEmitCacher : public PcodeEmit
{
public:
    // vector<unique_ptr<Varnode>> m_vars;
    vector<PcodeOp>             m_ops;

    PcodeEmitCacher() {
    }

    void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) {
        PcodeOp op;
        op.opcode = opc;

        if (outvar != nullptr) {
            op.output = *outvar;
        }

        if (vars != nullptr && isize > 0) {
            for (int i = 0; i < isize; i++) {
                op.inputs.push_back(vars[i]);
            }
        }
        m_ops.push_back(op);
    }
};

class AssemblyEmitCacher : public AssemblyEmit
{
public:
    Address  m_addr;
    string   m_mnem;
    string   m_body;

    void dump(const Address &addr, const string &mnem, const string &body)
    {
        m_addr = addr;
        m_mnem = mnem;
        m_body = body;
    };
};

class PcodeArchitecture : public Architecture {
    SimpleLoadImage     m_loader;
    ContextInternal     m_context_internal;
    DocumentStorage     m_document_storage;
    Document           *m_document;
    Element            *m_tags;
    std::unique_ptr<Sleigh>  m_sleigh;
    std::mutex m_sleigh_mutex;

    size_t m_addr_size;
    BNEndianness m_endianness;

public:
	PcodeArchitecture(const std::string& name): Architecture("pcode_" + name) {
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

        m_addr_size = m_sleigh->getDefaultCodeSpace()->getAddrSize();
        m_endianness = m_sleigh->getDefaultCodeSpace()->isBigEndian() ? BigEndian : LittleEndian;


        LogInfo("Done loading: %s", path.c_str());
	}

    BNEndianness GetEndianness() const override {
        return m_endianness;
    }

    size_t GetAddressSize() const override {
        return m_addr_size;
    }

    bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override {
        std::lock_guard<std::mutex> guard(m_sleigh_mutex);

        m_loader.setData(addr, data, maxLen);
        Address pcode_addr(m_sleigh->getDefaultCodeSpace(), addr);

        try {

            PcodeEmitCacher pcode;
            result.length = m_sleigh->oneInstruction(pcode, pcode_addr);

            for (auto const &op : pcode.m_ops) {
                // TODO: Do we need to deal with different addr spaces?
                switch(op.opcode) {
                case CPUI_BRANCH:
                    result.AddBranch(UnconditionalBranch, op.inputs[0].getAddr().getOffset());
                    break;
                case CPUI_CBRANCH:
                    result.AddBranch(TrueBranch, op.inputs[0].getAddr().getOffset());
                    result.AddBranch(FalseBranch, addr + result.length);
                    break;
                case CPUI_BRANCHIND:
                    // TODO
                    break;
                case CPUI_CALL:
                    result.AddBranch(CallDestination, op.inputs[0].getAddr().getOffset());
                    break;
                case CPUI_CALLIND:
                    // TODO
                    break;
                case CPUI_CALLOTHER:
                    // TODO
                    break;
                case CPUI_RETURN:
                    result.AddBranch(FunctionReturn);
                    break;
                }
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) override {
        std::lock_guard<std::mutex> guard(m_sleigh_mutex);

        m_loader.setData(addr, data, len);
        Address pcode_addr(m_sleigh->getDefaultCodeSpace(), addr);

        try {
            // Update length of actually processed instruction
            AssemblyEmitCacher assembly;
            len = m_sleigh->printAssembly(assembly, pcode_addr);

            result.push_back(InstructionTextToken(InstructionToken, assembly.m_mnem));
            result.push_back(InstructionTextToken(TextToken, " " + assembly.m_body));
            return true;
        } catch (...) {
            return false;
        }
    }

    std::optional<ExprId> ReadIL(LowLevelILFunction& il, VarnodeData data) {
        spacetype typ = data.space->getType();

        if (typ == IPTR_CONSTANT) {
            return il.Const(data.size, data.offset);
        } else if (typ == IPTR_PROCESSOR) { // Registers
            LogInfo("read reg %d %lx", data.size, data.offset);
        } else if (typ == IPTR_INTERNAL) {
            LogInfo("read internal %d %lx", data.size, data.offset);
        } else {
            LogInfo("read unknown space %d", typ);
        }
        return {};
    }

    ExprId WriteIL(LowLevelILFunction& il, VarnodeData dst, std::optional<ExprId> src) {
        if (!src) {
            return il.Undefined();
        }

        spacetype typ = dst.space->getType();

        if (typ == IPTR_CONSTANT) {
            return il.Undefined();
        } else if (typ == IPTR_PROCESSOR) { // Registers
            LogInfo("write reg %d %lx", dst.size, dst.offset);
            return il.SetRegister(dst.size, dst.offset / dst.size, *src);
        } else if (typ == IPTR_INTERNAL) {
            LogInfo("write internal %d %lx", dst.size, dst.offset);
        } else {
            LogInfo("write unknown space %d", typ);
        }
        return il.Undefined();
    }

    bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override {
        std::lock_guard<std::mutex> guard(m_sleigh_mutex);

        m_loader.setData(addr, data, len);
        Address pcode_addr(m_sleigh->getDefaultCodeSpace(), addr);

        try {

            PcodeEmitCacher pcode;
            AssemblyEmitCacher assembly;
            len = m_sleigh->oneInstruction(pcode, pcode_addr);

            for (auto const &op : pcode.m_ops) {
                if (op.opcode == CPUI_COPY) {
                    LogInfo("addr %lx", addr);

                    il.AddInstruction(WriteIL(il, *op.output, ReadIL(il, op.inputs[0])));
                } else if (op.opcode == CPUI_BRANCH) {
                    uint64_t target = op.inputs[0].getAddr().getOffset();
                    BNLowLevelILLabel* label = il.GetLabelForAddress(this, target);
                    if (label) {
                        il.AddInstruction(il.Goto(*label));
                    } else {
                        il.AddInstruction(il.Jump(il.ConstPointer(m_addr_size, target)));
                    }
                } else {
                    il.AddInstruction(il.Undefined());
                }
            }

            return true;
        } catch (...) {
            il.AddInstruction(il.Undefined());
            return false;
        }
    }



};


extern "C"
{
    BN_DECLARE_CORE_ABI_VERSION


    BINARYNINJAPLUGIN bool CorePluginInit() {
        try {
            Architecture* arch = new PcodeArchitecture("V850");
            Architecture::Register(arch);

            // BinaryViewType::RegisterArchitecture("ELF", 0x08, BigEndian, v850);
            return true;
        } catch (...) {
            return false;
        }
    }
}
