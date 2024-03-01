import keystone
import capstone
import ida_bytes
import idc
from module.utils import MAGIC

KS = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
CS = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

NOP_BYTES = b'\x1f\x20\x03\xd5'
def handle_txt(path):
    addr_dict = {}
    f = open(path)
    line = f.readline().replace("\n", "")
    while line:
        info = line.split(",")
        if len(info) == 2:
            patch_addr = info[0]
            b_addr = info[1]
            if patch_addr not in addr_dict.keys():
                addr_dict[patch_addr] = [b_addr]
            else:
                addr_list = addr_dict[patch_addr]
                if b_addr not in addr_list:
                    addr_dict[patch_addr].append(b_addr)
        elif len(info) == 3:
            patch_addr = info[0]
            b_addr1 = info[1]
            b_addr2 = info[2]
            if patch_addr not in addr_dict.keys():
                addr_dict[patch_addr] = [b_addr1, b_addr2]
            else:
                addr_list = addr_dict[patch_addr]
                if b_addr1 not in addr_list:
                    addr_dict[patch_addr].append(b_addr1)
                if b_addr2 not in addr_list:
                    addr_dict[patch_addr].append(b_addr1)
        else:
            raise Exception("check your code")
        line = f.readline().replace("\n", "")
    f.close()
    return addr_dict


def get_b_const_bytes(ea, const):
    '''
    返回例如 ea: b 0x12334的指令
    :param ea:
    :param const:
    :return:
    '''
    ea = int(ea, 16)
    CODE = f"b {const[0]}"
    encoding, count = KS.asm(CODE, ea)
    return ea, bytes(encoding)

def find_magic(ea):
    for i in range(10):
        asm = idc.GetDisasm(ea)
        if asm.startswith(MAGIC):
            info = asm.split(",")
            cond = info[-1].replace(" ","").lower()
            return ea, cond
        ea = idc.prev_head(ea)
    raise Exception("check your code:" + hex(ea))


def get_bxx_const_bytes(ea, const_list):
    ea = int(ea, 16)
    patch_ea, cond = find_magic(ea)
    code = f"b{cond} {const_list[0]}"
    encoding, count = KS.asm(code, patch_ea)
    ret = bytes(encoding)
    code = f"b {const_list[1]}"
    encoding, count = KS.asm(code, patch_ea + 4)
    ret += bytes(encoding)
    return patch_ea, ret


addr_dict = handle_txt("./addr.txt")

for key in addr_dict.keys():
    value = addr_dict[key]
    if len(value) == 1:
        ea, patch_bytes = get_b_const_bytes(key, value)
        ida_bytes.patch_bytes(ea, patch_bytes)
    else:
        ea, patch_bytes = get_bxx_const_bytes(key, value)
        ida_bytes.patch_bytes(ea, patch_bytes)