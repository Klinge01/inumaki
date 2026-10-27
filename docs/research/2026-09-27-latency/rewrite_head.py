# Exact algebraic rewrite of GLiNER markerV0 span head:
#   out = W2 relu(W1 relu([s_i; e_j]) + b1) + b2 ; logit_c = out . p_c
# = relu(A_i + B_j) . (W2^T p_c) + b2.p_c  with A = relu(S) W1a, B = relu(E) W1b + b1
import onnx, numpy as np, sys
from onnx import helper as h, numpy_helper as nh, TensorProto as TP
from common import GL
src = sys.argv[1] if len(sys.argv)>1 else GL+"/onnx/model_quantized.onnx"
dst = sys.argv[2] if len(sys.argv)>2 else "gliner_fasthead.onnx"
m = onnx.load(src); g = m.graph
init = {t.name: t for t in g.initializer}
byname = {n.name: n for n in g.node}
prod = {o: n for n in g.node for o in n.output}
def deq(prefix):
    q = nh.to_array(init[prefix+"_quantized"]).astype(np.float32)
    s = nh.to_array(init[prefix+"_scale"]).astype(np.float32); z = nh.to_array(init[prefix+"_zero_point"]).astype(np.float32)
    return (q - z) * s
W1 = deq("onnx::MatMul_1687"); W2 = deq("onnx::MatMul_1688")        # [1536,3072], [3072,768]
b1 = nh.to_array(init["core.span_rep_layer.span_rep_layer.out_project.0.bias"]); b2 = nh.to_array(init["core.span_rep_layer.span_rep_layer.out_project.3.bias"])
ge0 = byname["/core/span_rep_layer/span_rep_layer/GatherElements"]; ge1 = byname["/core/span_rep_layer/span_rep_layer/GatherElements_1"]
S, idx0 = ge0.input[0], ge0.input[1]; E, idx1 = ge1.input[0], ge1.input[1]
# idx tensors are (B,N,768) expands of (B,N,1): take the (B,N,1) source of each Expand
ex0 = prod[idx0]; ex1 = prod[idx1]
assert ex0.op_type == "Expand" and ex1.op_type == "Expand", (ex0.op_type, ex1.op_type)
ein = byname["/core/Einsum"]; span_rep_reshape_in, P = ein.input
reshape = byname["/core/span_rep_layer/span_rep_layer/Reshape_2"]; concat3 = prod[reshape.input[1]]
H = 3072
new_inits = [nh.from_array(W1[:768], "fh_W1a"), nh.from_array(W1[768:], "fh_W1b"), nh.from_array(b1, "fh_b1"),
             nh.from_array(np.ascontiguousarray(W2.T), "fh_W2T"), nh.from_array(b2.reshape(768,1), "fh_b2"),
             nh.from_array(np.array([1,1,H],np.int64), "fh_expand"), nh.from_array(np.array([0,2,1],np.int64), "fh_perm"),
             nh.from_array(np.array([-1],np.int64), "fh_minus1"),
             nh.from_array(np.array(0,np.int64), "fh_zero_s"), nh.from_array(np.array(1,np.int64), "fh_one_s"),
             nh.from_array(np.array([1],np.int64), "fh_ax1"), nh.from_array(np.array([2],np.int64), "fh_ax2"),
             nh.from_array(np.array([-1,H],np.int64), "fh_flat")]
nodes = [
  h.make_node("Relu",[S],["fh_Sr"]), h.make_node("Relu",[E],["fh_Er"]),
  h.make_node("MatMul",["fh_Sr","fh_W1a"],["fh_A"]),
  h.make_node("MatMul",["fh_Er","fh_W1b"],["fh_B0"]), h.make_node("Add",["fh_B0","fh_b1"],["fh_B"]),
  # flat row gather: rows of A/B are (b*L + word); batch offset b*L added to the (B,N) index
  h.make_node("Shape",["fh_A"],["fh_shA"]),
  h.make_node("Gather",["fh_shA","fh_zero_s"],["fh_Bsz_s"]), h.make_node("Gather",["fh_shA","fh_one_s"],["fh_Lsz"]),
  h.make_node("Range",["fh_zero_s","fh_Bsz_s","fh_one_s"],["fh_br"]),
  h.make_node("Mul",["fh_br","fh_Lsz"],["fh_off0"]), h.make_node("Unsqueeze",["fh_off0","fh_ax1"],["fh_off"]),
  h.make_node("Squeeze",[ex0.input[0],"fh_ax2"],["fh_j0"]), h.make_node("Squeeze",[ex1.input[0],"fh_ax2"],["fh_j1"]),
  h.make_node("Add",["fh_j0","fh_off"],["fh_k0"]), h.make_node("Add",["fh_j1","fh_off"],["fh_k1"]),
  h.make_node("Reshape",["fh_A","fh_flat"],["fh_Af"]), h.make_node("Reshape",["fh_B","fh_flat"],["fh_Bf"]),
  h.make_node("Gather",["fh_Af","fh_k0"],["fh_As"],axis=0), h.make_node("Gather",["fh_Bf","fh_k1"],["fh_Bs"],axis=0),
  h.make_node("Add",["fh_As","fh_Bs"],["fh_Hs0"]), h.make_node("Relu",["fh_Hs0"],["fh_Hs"]),
  h.make_node("MatMul",[P,"fh_W2T"],["fh_U"]),                     # (B,C,3072)
  h.make_node("Transpose",["fh_U"],["fh_UT"],perm=[0,2,1]),         # (B,3072,C)
  h.make_node("MatMul",["fh_Hs","fh_UT"],["fh_L0"]),                # (B,N,C)
  h.make_node("MatMul",[P,"fh_b2"],["fh_c"]),                       # (B,C,1)
  h.make_node("Transpose",["fh_c"],["fh_cT"],perm=[0,2,1]),         # (B,1,C)
  h.make_node("Add",["fh_L0","fh_cT"],["fh_L"]),
  h.make_node("Concat",[concat3.input[0],concat3.input[1],concat3.input[2],"fh_minus1"],["fh_shape"],axis=0),
  h.make_node("Reshape",["fh_L","fh_shape"],[ein.output[0]]),
]
keep = [n for n in g.node if n is not ein]
del g.node[:]; g.node.extend(keep + nodes); g.initializer.extend(new_inits)
# drop now-dead nodes
out_names = {o.name for o in g.output}
while True:
    used = {i for n in g.node for i in n.input} | out_names
    dead = [n for n in g.node if not any(o in used for o in n.output)]
    if not dead: break
    for n in dead: g.node.remove(n)
used = {i for n in g.node for i in n.input}
live = [t for t in g.initializer if t.name in used]; del g.initializer[:]; g.initializer.extend(live)
onnx.checker.check_model(m); onnx.save(m, dst); print("wrote", dst)
