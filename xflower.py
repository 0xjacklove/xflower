#! -*- coding=utf-8 -*-
import capstone
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.utils import *
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprMem, ExprId, ExprInt, ExprAssign, ExprAff, ExprCompose, ExprOp, ExprCond
from elftools.elf.elffile import ELFFile

from module.utils import replace_exprcond, MAGIC
from module.my_symbexec import MySymbolicExecutionEngine

CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)


def read_data_section(elf_path, seg_name):
    with open(elf_path, 'rb') as file:
        elffile = ELFFile(file)

        # 获取.data段
        data_section = elffile.get_section_by_name(seg_name)

        # 检查是否存在.data段
        if not data_section:
            print("The file does not have a .data section.")
            return None

        # 读取.data段数据
        data = data_section.data()
        return data, data_section.header.sh_addr


def get_bin(path):
    fp = open(path, 'rb')
    buffer = fp.read()
    fp.close()
    return buffer


def fill_data(sb, offset, data):
    data = list(data)
    for i in range(len(data)):
        sb.symbols[ExprMem(ExprInt(offset + i, 64), 8)] = ExprInt(data[i], 8)


def add_block(asmcfg, offset):
    block, next1 = mdis._dis_block(offset)
    asmcfg.add_block(block)


def print_blocks(asmcfg):
    for block in asmcfg.blocks:
        print(block)


def get_code_disam(addr, code):
    codes = []
    for i in CS.disasm(code, addr):
        codes.append(i)
    return codes


def get_all_condition_addr(asm, magic="csel"):
    condition_pc = []
    for i in range(len(asm)):
        ins = asm[i]
        if ins.mnemonic == "br":
            # 开始向上寻找
            for j in range(i, 0, -1):
                magic_ins = asm[j]
                if magic_ins.mnemonic == magic.lower():
                    condition_pc.append(magic_ins.address)
                    break
                if i - j > 10:
                    raise Exception("check this br" + str(ins))
    return condition_pc


def init_machine(extra_blocks, condition, jmp_dict={}):
    lifter = machine.lifter_model_call(loc_db)
    asmcfg = mdis.dis_multiblock(start_addr)
    for block in extra_blocks:
        add_block(asmcfg, block)
    print_blocks(asmcfg)
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
    sb = MySymbolicExecutionEngine(lifter, condition_pc=condition, jmp_dict=jmp_dict, path=addr_path)

    fill_data(sb, data_offset, data)
    fill_data(sb, got_data_offset, got_data)
    # fill_data(sb, bss_data_offset, bss_data)

    for i in range(8):
        sb.symbols[ExprMem(ExprInt(0 + i, 64), 8)] = ExprInt(0, 8)
    return sb, ircfg


def handle(blocks, condition, jmp_dict):
    print("[*]*****************************************************************")
    sb, ircfg = init_machine(blocks, condition, jmp_dict)
    try:
        symbolic_pc = sb.run_at(ircfg, start_addr, step=True)
    except Exception as e:
        print("--------Exception---------")
        print(e)
        return
    if symbolic_pc is not None and str(symbolic_pc) != "LR":
        if not symbolic_pc.is_cond():
            pc = sb.pc
            if type(symbolic_pc.arg) == int:
                next_pc = symbolic_pc.arg
                # fp.write(f"{hex(pc)},{hex(next_pc)}\n")
                if next_pc not in blocks and next_pc < end_addr:
                    blocks.append(next_pc)
                    handle(blocks, condition, jmp_dict)
            else:
                expr_list = replace_exprcond(symbolic_pc)
                next_pc_list = []
                for expr in expr_list:
                    simp_expr = sb.eval_expr(sb.expr_simp(expr))
                    if simp_expr not in next_pc_list:
                        next_pc_list.append(simp_expr)

                if len(next_pc_list) == 2:
                    src1 = next_pc_list[0].arg
                    src2 = next_pc_list[1].arg
                    if src1 not in blocks and src1 < end_addr:
                        blocks.append(src1)
                        jmp_dict[pc] = next_pc_list[0]
                        handle(blocks, condition, jmp_dict)
                    if src2 not in blocks and src2 < end_addr:
                        blocks.append(src2)
                        jmp_dict[pc] = next_pc_list[1]
                        handle(blocks, condition, jmp_dict)
                elif len(next_pc_list) == 1:
                    next_pc = next_pc_list[0].arg
                    if next_pc not in blocks and next_pc < end_addr:
                        blocks.append(next_pc)
                        handle(blocks, condition, jmp_dict)
                else:
                    raise Exception("you need check your code")
        else:
            pc = sb.pc
            src1 = sb.eval_expr(symbolic_pc.src1).arg
            src2 = sb.eval_expr(symbolic_pc.src2).arg
            # fp.write(f"{hex(pc)},{hex(src1)},{hex(src2)}\n")
            if src1 not in blocks and src1 < end_addr:
                blocks.append(src1)
                jmp_dict[pc] = symbolic_pc.src1
                handle(blocks, condition, jmp_dict)
            if src2 not in blocks and src2 < end_addr:
                blocks.append(src2)
                jmp_dict[pc] = symbolic_pc.src2
                handle(blocks, condition, jmp_dict)


path = "./lib52pojie.so"
addr_path = "./addr.txt"
f = open(addr_path, "w")
f.close()
# 使用函数读取ELF文件的.data段
data, data_offset = read_data_section(path, '.data')
got_data, got_data_offset = read_data_section(path, '.got')
# bss_data, bss_data_offset = read_data_section(path, '.bss')
code_buffer = get_bin(path)
machine = Machine('aarch64l')
loc_db = LocationDB()
c = Container.from_string(code_buffer, loc_db)
mdis = machine.dis_engine(c.bin_stream, loc_db=loc_db)

start_addr = 0x1A864
end_addr = 0x1AE20
func_code = code_buffer[start_addr:end_addr]
asm = get_code_disam(start_addr, func_code)
condition = get_all_condition_addr(asm, MAGIC)
handle([], condition, {})
