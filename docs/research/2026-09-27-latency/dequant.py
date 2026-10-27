# Turn a dynamic-int8 ONNX graph back into fp32 (weights = dequantized int8 values).
import onnx, numpy as np, sys
from onnx import helper as h, numpy_helper as nh
src, dst = sys.argv[1], sys.argv[2]
m = onnx.load(src); g = m.graph
init = {t.name: t for t in g.initializer}
prod = {o: n for n in g.node for o in n.output}
cons = {}
for n in g.node:
    for i in n.input: cons.setdefault(i, []).append(n)
def deq(qname, zname, sname):
    q = nh.to_array(init[qname]).astype(np.float32); z = nh.to_array(init[zname]).astype(np.float32); s = nh.to_array(init[sname]).astype(np.float32)
    return ((q - z) * s).astype(np.float32)
newn, newi, kill = [], [], set()
for n in list(g.node):
    if n.op_type == "MatMulInteger" and n.input[1] in init:
        dql = prod[n.input[0]]; assert dql.op_type == "DynamicQuantizeLinear"
        x = dql.input[0]
        base = n.input[1][:-len("_quantized")]
        W = deq(n.input[1], n.input[3], base + "_scale")
        cast = cons[n.output[0]][0]; mul = [c for c in cons[cast.output[0]] if c.op_type == "Mul"][0]
        wn = base + "_fp32"; newi.append(nh.from_array(W, wn))
        newn.append(h.make_node("MatMul", [x, wn], [mul.output[0]], name=n.name + "_fp32"))
        kill |= {n.name, cast.name, mul.name}
    elif n.op_type == "DequantizeLinear" and n.input[0] in prod and prod[n.input[0]].op_type == "Gather" and prod[n.input[0]].input[0] in init:
        gat = prod[n.input[0]]; qn = gat.input[0]
        W = deq(qn, n.input[2], n.input[1]); wn = qn + "_fp32"; newi.append(nh.from_array(W, wn))
        newn.append(h.make_node("Gather", [wn, gat.input[1]], [n.output[0]], name=gat.name + "_fp32", **{a.name: h.get_attribute_value(a) for a in gat.attribute}))
        kill |= {n.name, gat.name}
keep = [n for n in g.node if n.name not in kill]
del g.node[:]; g.node.extend(keep + newn); g.initializer.extend(newi)
outs = {o.name for o in g.output}
while True:
    used = {i for n in g.node for i in n.input} | outs
    dead = [n for n in g.node if not any(o in used for o in n.output)]
    if not dead: break
    for n in dead: g.node.remove(n)
used = {i for n in g.node for i in n.input}
live = [t for t in g.initializer if t.name in used]; del g.initializer[:]; g.initializer.extend(live)
# topological sort
avail = {i.name for i in g.input} | {t.name for t in g.initializer} | {""}
order, pending = [], list(g.node)
while pending:
    rest = []
    for n in pending:
        if all(i in avail for i in n.input): order.append(n); avail |= set(n.output)
        else: rest.append(n)
    assert len(rest) < len(pending), "cycle"; pending = rest
del g.node[:]; g.node.extend(order)
onnx.save(m, dst, save_as_external_data=False) if m.ByteSize() < 2**31 - 1 else onnx.save(m, dst, save_as_external_data=True)
import collections; print(dst, collections.Counter(n.op_type for n in g.node).most_common(8))
