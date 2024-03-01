from miasm.expression.expression import ExprId, ExprInt, ExprCompose, ExprCond
from miasm.expression.simplifications import expr_simp_explicit
from miasm.ir.symbexec import SymbolicExecutionEngine

from module.utils import replace_exprcond, replace_exprcond2


class MySymbolicExecutionEngine(SymbolicExecutionEngine):
    def __init__(self, lifter, condition_pc=[], jmp_dict={}, state=None, sb_expr_simp=expr_simp_explicit,
                 show_mem=False, path=None):
        super().__init__(lifter, state, sb_expr_simp)
        self.show_mem = show_mem
        self.condition_pc = condition_pc
        self.pc = None
        self.instr = None
        self.path = path
        self.jmp_dict = jmp_dict

    def write(self, content):
        with open(self.path, "a+") as f:
            f.write(content)

    def eval_updt_irblock(self, irb, step=False):
        """
        Symbolic execution of the @irb on the current state
        @irb: irbloc instance
        @step: display intermediate steps
        """
        for assignblk in irb:
            self.pc = assignblk.instr.offset
            self.instr = assignblk.instr
            if step:
                print(hex(assignblk.instr.offset) + ":", assignblk.instr)
                print('Assignblk:')
                print(assignblk)
                print('_' * 80)

            if assignblk.instr.offset in self.condition_pc:
                # handle cesl
                assigns_key = next(iter(assignblk._assigns.keys()))
                assigns_value = assignblk._assigns[assigns_key]
                assignblk._assigns[assigns_key] = replace_exprcond2(assigns_value)

            self.eval_updt_assignblk(assignblk)

            if assignblk.instr.offset in self.jmp_dict.keys():
                self.symbols.symbols_id[ExprId("PC", 64)] = self.eval_expr(self.jmp_dict[assignblk.instr.offset])
                self.symbols.symbols_id[ExprId("IRDst", 64)] = self.eval_expr(self.jmp_dict[assignblk.instr.offset])

            if step:
                self.dump(mems=False)
                '''
                内存打印太多了
                '''
                # if assignblk.instr.offset == 0xca768:
                #     self.dump(ids=False)
                print('_' * 80)

            if assignblk.instr.name == "BR":
                symbolic_pc = self.symbols.symbols_id[assignblk.instr.args[0]]
                if not symbolic_pc.is_cond():
                    pc = self.pc
                    if type(symbolic_pc.arg) == int:
                        next_pc = symbolic_pc.arg
                        self.write(f"{hex(pc)},{hex(next_pc)}\n")
                    else:
                        expr_list = replace_exprcond(symbolic_pc)
                        next_pc_list = []
                        for expr in expr_list:
                            simp_expr = self.eval_expr(self.expr_simp(expr))
                            if simp_expr not in next_pc_list:
                                next_pc_list.append(simp_expr)

                        if len(next_pc_list) == 2:
                            src1 = next_pc_list[0].arg
                            src2 = next_pc_list[1].arg
                            self.write(f"{hex(pc)},{hex(src1)},{hex(src2)}\n")
                        elif len(next_pc_list) == 1:
                            next_pc = next_pc_list[0].arg
                            self.write(f"{hex(pc)},{hex(next_pc)}\n")
                        else:
                            raise Exception("you need check your code")
                else:
                    pc = self.pc
                    src1 = int(str(self.eval_expr(symbolic_pc.src1)), 16)
                    src2 = int(str(self.eval_expr(symbolic_pc.src2)), 16)
                    self.write(f"{hex(pc)},{hex(src1)},{hex(src2)}\n")

        dst = self.eval_expr(self.lifter.IRDst)

        return dst

    def run_at(self, ircfg, addr, lbl_stop=None, step=False):
        """
        Symbolic execution starting at @addr
        @addr: address to execute (int or ExprInt or label)
        @lbl_stop: LocKey to stop execution on
        @step: display intermediate steps
        """
        i = 0
        while True:
            irblock = ircfg.get_block(addr)
            if irblock is None:
                break
            if irblock.loc_key == lbl_stop:
                break
            addr = self.eval_updt_irblock(irblock, step=step)
            i += 1
            # 死循环跳出
            if i > 10000:
                print("[*] meet loop")
                return None
        return addr
