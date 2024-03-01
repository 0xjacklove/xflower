from itertools import product

from miasm.expression.expression import ExprCond, ExprCompose, ExprOp, ExprMem, ExprId

MAGIC = "CSEL"
def replace_exprcond(expr):
    if isinstance(expr, ExprCond):
        # 对条件表达式的每个分支进行递归替换
        src1 = replace_exprcond(expr.src1)
        src2 = replace_exprcond(expr.src2)
        # 生成两个新的表达式，分别代表条件成立或不成立的情况
        return [src1, src2]
    elif isinstance(expr, ExprCompose):
        # 对ExprCompose中的每个部分进行递归替换，并处理返回的元组
        parts = [replace_exprcond(arg) for arg in expr.args]
        # 检查是否有任何部分返回了一个列表（多个替换结果）
        if any(isinstance(part, list) for part in parts):
            # 确保每个部分都是列表，单个结果转换为列表
            parts = [(part if isinstance(part, list) else [part]) for part in parts]
            # 生成所有可能的ExprCompose对象
            ret = [ExprCompose(*combination) for combination in product(*parts)]
        else:
            # 如果没有列表，说明没有多个替换结果，直接返回原始ExprCompose
            ret = [ExprCompose(*parts)]
        return ret
    elif isinstance(expr, ExprOp):
        # 对ExprOp的每个参数进行递归替换
        parts = [replace_exprcond(arg) for arg in expr.args]
        # 检查是否有任何部分返回了一个列表（多个替换结果）
        if any(isinstance(part, list) for part in parts):
            # 确保每个部分都是列表，单个结果转换为列表
            parts = [(part if isinstance(part, list) else [part]) for part in parts]
            # 生成所有可能的ExprOp对象
            ret = [ExprOp(expr.op, *combination) for combination in product(*parts)]
        else:
            # 如果没有列表，说明没有多个替换结果，直接返回原始ExprOp
            ret = [ExprOp(expr.op, *parts)]
        return ret

    elif isinstance(expr, ExprMem):
        # 对ExprMem的参数进行递归替换
        if type(expr.arg) != int:
            addr = replace_exprcond(expr.arg)
            # 如果递归替换的结果是一个列表（即存在多个可能的地址），则生成多个ExprMem对象
            if isinstance(addr, list):
                ret = [ExprMem(a, expr.size) for a in addr]
            else:
                # 如果没有列表，说明没有多个替换结果，直接返回原始ExprMem
                ret = [ExprMem(addr, expr.size)]
            return ret
        else:
            return expr
    else:
        # 对于其他类型的表达式（如ExprId, ExprInt等），直接返回
        return expr

def replace_exprcond2(expr):
    if isinstance(expr, ExprCond):
        # 对条件表达式的每个分支进行递归替换
        src1 = replace_exprcond2(expr.src1)
        src2 = replace_exprcond2(expr.src2)
        # 生成两个新的表达式，分别代表条件成立或不成立的情况
        return ExprCond(ExprId("SuperMan", 64), src1, src2)

    elif isinstance(expr, ExprOp):
        # 对ExprOp的每个参数进行递归替换
        parts = [replace_exprcond2(arg) for arg in expr.args]
        ret = ExprOp(expr.op, *parts)
        return ret

    else:
        # 对于其他类型的表达式（如ExprId, ExprInt等），直接返回
        return expr