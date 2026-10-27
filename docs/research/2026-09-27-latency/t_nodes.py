import json, collections, onnxruntime as ort
from common import *
text=open("text5k.txt").read(); cs=chunks(text); g=Gliner(); f=g.prep(cs[0])
so=ort.SessionOptions(); so.intra_op_num_threads=4; so.enable_profiling=True
s=ort.InferenceSession(GL+"/onnx/model_quantized.onnx", so, providers=["CPUExecutionProvider"])
for _ in range(3): s.run(None,f)
ev=json.load(open(s.end_profiling())); agg=collections.defaultdict(lambda:[0,None,None]); tot=0
for e in ev:
    if e.get("cat")=="Node" and e["name"].endswith("_kernel_time"):
        k=e["name"][:-12]; agg[k][0]+=e["dur"]; agg[k][1]=e["args"]["op_name"]; agg[k][2]=e["args"].get("input_type_shape"); tot+=e["dur"]
print("total per run ms", tot/3000)
for k,(d,op,shp) in sorted(agg.items(), key=lambda x:-x[1][0])[:14]:
    print(f"{100*d/tot:5.1f}% {op:24} {k[:60]:60} {json.dumps(shp)[:150]}")
