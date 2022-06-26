#define _CRT_SECURE_NO_WARNINGS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <cassert>
#include <mutex>
#include <map>

#include "third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.hh"
#include "third_party/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/loadimage.hh"

#include <QDirIterator>
#include <QTemporaryFile>
#include <QProcessEnvironment>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;

template<typename ... Args>
std::string format( const std::string& format, Args ... args )
{
    int size_s = std::snprintf( nullptr, 0, format.c_str(), args ... ) + 1; // Extra space for '\0'
    if( size_s <= 0 ){ throw std::runtime_error( "Error during formatting." ); }
    auto size = static_cast<size_t>( size_s );
    std::unique_ptr<char[]> buf( new char[ size ] );
    std::snprintf( buf.get(), size, format.c_str(), args ... );
    return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
}

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

    std::map<int, VarnodeData> m_register_varnodes;
    std::map<int, std::string> m_register_names;
    std::map<VarnodeData, int> m_register_nums;
    std::vector<std::string>   m_userops;

    size_t m_addr_size;
    BNEndianness m_endianness;

public:
    PcodeArchitecture(QFileInfo sla): Architecture("pcode_" + sla.baseName().toStdString()) {
        QFile qrc_file(sla.absoluteFilePath());
        QTemporaryFile * tmp_file = QTemporaryFile::createNativeFile(qrc_file); // Returns a pointer to a temporary file
        const std::string tmp_path = tmp_file->fileName().toStdString();

        qWarning() << "Loading" << sla.baseName();
        try {
            m_document = m_document_storage.openDocument(tmp_path);
            m_tags = m_document->getRoot();
            m_document_storage.registerTag(m_tags);
        } catch (...) {
            LogError("Error opening %s", tmp_path.c_str());
            throw;
        }

        m_sleigh.reset(new Sleigh(&m_loader, &m_context_internal));
        m_sleigh->initialize(m_document_storage);

        // TODO: get from pspec
        if (sla.baseName() == "x86-64") {
            m_sleigh->setContextDefault("addrsize", 2);
            m_sleigh->setContextDefault("bit64", 1);
            m_sleigh->setContextDefault("opsize", 1);
            m_sleigh->setContextDefault("rexprefix", 0);
            m_sleigh->setContextDefault("longMode", 1);
        }

        m_addr_size = m_sleigh->getDefaultCodeSpace()->getAddrSize();
        m_endianness = m_sleigh->getDefaultCodeSpace()->isBigEndian() ? BigEndian : LittleEndian;

        // Registers
        std::map<VarnodeData, std::string> registers;
        m_sleigh->getAllRegisters(registers);
        int i = 0;
        for (auto const& [varnode, name] : registers) {
            LogInfo("%d - size %d offset %ld name %s", i, varnode.size, varnode.offset, name.c_str());
            m_register_nums[varnode] = i;
            m_register_varnodes[i] = varnode;
            m_register_names[i] = name;
            i++;
        }

        // Userops
        m_sleigh->getUserOpNames(m_userops);
        i = 0;
        for (auto const &op : m_userops) {
            LogInfo("%d - %s", i, op.c_str());
            i++;
        }
    }

    BNEndianness GetEndianness() const override {
        return m_endianness;
    }

    size_t GetAddressSize() const override {
        return m_addr_size;
    }

    virtual vector<uint32_t> GetFullWidthRegisters() override {
        std::vector<uint32_t> res;
        for (auto const& [num, varnode] : m_register_varnodes) {
            res.push_back(num);
        }
        return res;
    }

    virtual vector<uint32_t> GetAllRegisters() override {
        std::vector<uint32_t> res;
        for (auto const& [num, varnode] : m_register_varnodes) {
            res.push_back(num);
        }
        return res;
    }

    virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override {
        VarnodeData reg_node = m_register_varnodes[reg];

        // TODO, handle overlapping registers
        BNRegisterInfo result = {reg, 0, reg_node.size, NoExtend};
        return result;
    }

    virtual string GetRegisterName(uint32_t reg) override {
        return m_register_names[reg];
    }

    virtual string GetIntrinsicName(uint32_t intrinsic) override {
        return m_userops[intrinsic];
    }

    virtual string GetFlagName(uint32_t reg) override {
        stringstream ss;
        ss << std::setfill ('0') << std::setw(4) << std::hex << reg;
        return "$U" + ss.str();
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
            AssemblyEmitCacher assembly;

            // Update length of actually processed instruction
            len = m_sleigh->printAssembly(assembly, pcode_addr);

            result.push_back(InstructionTextToken(InstructionToken, assembly.m_mnem));
            result.push_back(InstructionTextToken(TextToken, " " + assembly.m_body));
            return true;
        } catch (...) {
            return false;
        }
    }

    ExprId ILReadVarNode(LowLevelILFunction& il, VarnodeData data) {
        spacetype typ = data.space->getType();

        if (typ == IPTR_CONSTANT) {
            return il.Const(data.size, data.offset);
        } else if (typ == IPTR_PROCESSOR) { // Registers
            return il.Register(data.size, m_register_nums[data]);
        } else if (typ == IPTR_INTERNAL) { // Temporaries
            return il.LowPart(data.size, il.Flag(data.offset));
        } else {
            LogWarn("read unknown space %d", typ);
            return il.Undefined();
        }
    }

    ExprId ILWriteVarnode(LowLevelILFunction& il, VarnodeData dst, ExprId src) {
        spacetype typ = dst.space->getType();

        if (typ == IPTR_PROCESSOR) { // Registers
            return il.SetRegister(dst.size, m_register_nums[dst], src);
        } else if (typ == IPTR_INTERNAL) { // Temporaries
            ExprId tmp = il.LowPart(dst.size, src); // Truncate to output size
            return il.SetFlag(dst.offset, tmp);
        } else {
            LogWarn("write unknown space %d", typ);
            return il.Undefined();
        }
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
                if (op.opcode == CPUI_COPY) { // 1
                    il.AddInstruction(ILWriteVarnode(il, *op.output, ILReadVarNode(il, op.inputs[0])));
                } else if (op.opcode == CPUI_LOAD) { // 2
                    // Output contains destination
                    // Input 0 contains some information about the space, assume this is RAM for now
                    // Input 1 is a temporary with an offset in the space
                    ExprId offset = ILReadVarNode(il, op.inputs[1]);
                    ExprId val = il.Load(op.output->size, offset);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, val));
                } else if (op.opcode == CPUI_STORE) { // 3
                    // Input 0 contains some information about the space, assume this is RAM for now
                    // Input 1 is a temporary with an offset in the space
                    // Input 2 is the value to store
                    ExprId val = ILReadVarNode(il, op.inputs[2]);
                    ExprId offset = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(il.Store(op.inputs[1].size, offset, val));
                } else if (op.opcode == CPUI_BRANCH) { // 4
                    //https://github.com/Vector35/arch-mips/blob/staging/il.cpp#L144
                    uint64_t target = op.inputs[0].getAddr().getOffset();

                    BNLowLevelILLabel* label = il.GetLabelForAddress(this, target);
                    if (label) {
                        il.AddInstruction(il.Goto(*label));
                    } else {
                        il.AddInstruction(il.Jump(il.ConstPointer(m_addr_size, target)));
                    }
                } else if (op.opcode == CPUI_CBRANCH) { // 5
                    //https://github.com/Vector35/arch-mips/blob/staging/il.cpp#L154
                    ExprId cond = ILReadVarNode(il, op.inputs[1]);

                    uint64_t target_true = op.inputs[0].getAddr().getOffset();
                    uint64_t target_false = addr + len;

                    BNLowLevelILLabel* label_true = il.GetLabelForAddress(this, target_true);
                    BNLowLevelILLabel* label_false = il.GetLabelForAddress(this, target_false);

                    // Jump to label if it exists, otherwise create it
                    LowLevelILLabel code_true, code_false;
                    if (label_true && label_false) {
                        il.AddInstruction(il.If(cond, *label_true, *label_false));
                    } else if (label_true) {
                        il.AddInstruction(il.If(cond, *label_true, code_false));
                        il.MarkLabel(code_false);
                        il.AddInstruction(il.Jump(il.ConstPointer(m_addr_size, target_false)));
                    } else if (label_false) {
                        il.AddInstruction(il.If(cond, code_true, *label_false));
                        il.MarkLabel(code_true);
                        il.AddInstruction(il.Jump(il.ConstPointer(m_addr_size, target_true)));
                    } else {
                        il.AddInstruction(il.If(cond, code_true, code_false));
                        il.MarkLabel(code_true);
                        il.AddInstruction(il.Jump(il.ConstPointer(m_addr_size, target_true)));
                        il.MarkLabel(code_false);
                        il.AddInstruction(il.Jump(il.ConstPointer(m_addr_size, target_false)));
                    }
                } else if (op.opcode == CPUI_CALL){ // 7
                    uint64_t target = op.inputs[0].getAddr().getOffset();
                    il.AddInstruction(il.Call(il.ConstPointer(m_addr_size, target)));
                } else if (op.opcode == CPUI_CALLIND){ // 8
                    ExprId target = ILReadVarNode(il, op.inputs[0]);
                    il.AddInstruction(il.Call(target));
                } else if (op.opcode == CPUI_CALLOTHER){ // 10
                    il.AddInstruction(il.Intrinsic({}, op.inputs[0].offset, {}));
                } else if (op.opcode == CPUI_RETURN){ // 10
                    il.AddInstruction(il.Return(ILReadVarNode(il, op.inputs[0])));
                } else if (op.opcode == CPUI_INT_EQUAL){ // 11
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.CompareEqual(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_NOTEQUAL){ // 12
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.CompareNotEqual(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_SLESS){ // 13
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.CompareSignedLessThan(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_SLESSEQUAL){ // 14
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.CompareSignedLessEqual(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_LESS){ // 15
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.CompareUnsignedLessThan(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_LESSEQUAL){ // 16
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.CompareUnsignedLessEqual(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_ZEXT){ // 17
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.ZeroExtend(op.output->size, a)));
                } else if (op.opcode == CPUI_INT_SEXT){ // 18
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.SignExtend(op.output->size, a)));
                } else if (op.opcode == CPUI_INT_ADD){ // 19
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.Add(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_SUB){ // 20
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.Sub(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_CARRY){ // 21
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    ExprId res = il.Add(op.inputs[0].size + 1, a, b);
                    ExprId carry = il.And(op.inputs[0].size, il.LogicalShiftRight(op.inputs[0].size, res, il.Const(4, op.inputs[0].size * 8)), il.Const(4, 1));
                    il.AddInstruction(ILWriteVarnode(il, *op.output, carry));
                } else if (op.opcode == CPUI_INT_SCARRY){ // 22
                    // Does this work?
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(il.AddCarry(op.inputs[0].size, a, b, il.Flag(op.output->offset), 1));
                } else if (op.opcode == CPUI_INT_NEGATE){ // 25
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.Neg(op.output->size, a)));
                } else if (op.opcode == CPUI_INT_XOR){ // 26
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.Xor(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_AND){ // 27
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.And(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_OR){ // 28
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.Or(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_LEFT){ // 29
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.ShiftLeft(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_RIGHT){ // 30
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.LogicalShiftRight(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_SRIGHT){ // 31
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.ArithShiftRight(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_MULT){ // 32
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.Mult(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_DIV){ // 33
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.DivUnsigned(op.output->size, a, b)));
                } else if (op.opcode == CPUI_INT_SDIV){ // 34
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    il.AddInstruction(ILWriteVarnode(il, *op.output, il.DivSigned(op.output->size, a, b)));
                } else if (op.opcode == CPUI_BOOL_NEGATE){ // 37
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId out = il.CompareEqual(op.output->size, a, il.Const(op.output->size, 0));
                    il.AddInstruction(ILWriteVarnode(il, *op.output, out));
                } else if (op.opcode == CPUI_BOOL_XOR){ // 38
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    ExprId out = il.BoolToInt(op.output->size, il.Xor(op.output->size, a, b));
                    il.AddInstruction(ILWriteVarnode(il, *op.output, out));
                } else if (op.opcode == CPUI_BOOL_AND){ // 39
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    ExprId out = il.BoolToInt(op.output->size, il.And(op.output->size, a, b));
                    il.AddInstruction(ILWriteVarnode(il, *op.output, out));
                } else if (op.opcode == CPUI_BOOL_OR){ // 40
                    ExprId a = ILReadVarNode(il, op.inputs[0]);
                    ExprId b = ILReadVarNode(il, op.inputs[1]);
                    ExprId out = il.BoolToInt(op.output->size, il.Or(op.output->size, a, b));
                    il.AddInstruction(ILWriteVarnode(il, *op.output, out));
                } else if (op.opcode == CPUI_SUBPIECE){ // 63
                    ExprId a = il.LowPart(op.inputs[1].size, ILReadVarNode(il, op.inputs[0]));
                    il.AddInstruction(ILWriteVarnode(il, *op.output, a));
                } else {
                    stringstream ss;
                    ss << format("[0x%lx] unknown opcode %d ", addr, op.opcode);
                    if (op.output) {
                        ss << format("output - space: %d - size: %d - offset: 0x%lx, ", op.output->space->getType(), op.output->size, op.output->offset);
                    }
                    for (int i = 0; i < op.inputs.size(); i++) {
                        ss << format("input[%d] - space: %d - size: %d - offset: 0x%lx, ", i, op.inputs[i].space->getType(), op.inputs[i].size, op.inputs[i].offset);
                    }
                    LogInfo("%s", ss.str().c_str());
                }
            }

            return true;
        } catch (...) {
            return false;
        }
    }



};


extern "C"
{
    BN_DECLARE_CORE_ABI_VERSION


    BINARYNINJAPLUGIN bool CorePluginInit() {
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();

        if (!env.contains("LOAD_SLA")) {
            QDirIterator it(":/out/sla", QDirIterator::Subdirectories);
            stringstream ss;
            while (it.hasNext()) {
                it.next();
                ss << it.fileInfo().baseName().toStdString() << " ";
            }
            qWarning().noquote() << "LOAD_SLA environment variable not set. Available values: all" << QString::fromStdString(ss.str());
        }

        QString to_load = env.value("LOAD_SLA", "all");

        QDirIterator it(":/out/sla", QDirIterator::Subdirectories);
        while (it.hasNext()) {
            it.next();
            QFileInfo f = it.fileInfo();
            if (f.baseName() != to_load && to_load != "all") {
                continue;
            }

            Architecture* arch = new PcodeArchitecture(f);
            Architecture::Register(arch);
        }

        return true;
    }
}
