# Re-encode uint8 asymmetric per-tensor MatMulInteger weights as int8 symmetric per-channel (zp=0),
# the layout ORT's KleidiAI (Arm SME) and x86 AVX-VNNI U8S8 kernels take.
import onnx, numpy as np, sys
from onnx import numpy_helper as nh
src, dst = sys.argv[1], sys.argv[2]
m = onnx.load(src); init = {t.name: t for t in m.graph.initializer}
n = 0; err = 0.0
for node in m.graph.node:
    if node.op_type != "MatMulInteger": continue
    b = node.input[1]
    if b not in init or init[b].data_type != onnx.TensorProto.UINT8: continue
    base = b[:-len("_quantized")]
    q = nh.to_array(init[b]).astype(np.float32); zp = float(nh.to_array(init[base+"_zero_point"])); s = float(nh.to_array(init[base+"_scale"]))
    W = (q - zp) * s
    sc = np.maximum(np.abs(W).max(axis=0), 1e-12) / 127.0
    q8 = np.clip(np.round(W / sc), -127, 127).astype(np.int8)
    err = max(err, float(np.abs(q8 * sc - W).max() / (np.abs(W).max())))
    init[b].CopyFrom(nh.from_array(q8, b))
    init[base+"_zero_point"].CopyFrom(nh.from_array(np.zeros(W.shape[1], np.int8), base+"_zero_point"))
    init[base+"_scale"].CopyFrom(nh.from_array(sc.astype(np.float32), base+"_scale"))
    n += 1
onnx.save(m, dst); print(f"requantized {n} weights, max rel err {err:.4f}", dst)
