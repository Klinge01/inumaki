import onnxruntime as ort, sys
from common import *; from decode import decode
text=open("text5k.txt").read(); cs=chunks(text); g=Gliner(); feeds=[g.prep(c) for c in cs]
thr=[0.5,0.5,0.5,0.5,0.5,0.6,0.6]
def mk(p,th):
    so=ort.SessionOptions(); so.intra_op_num_threads=th
    return ort.InferenceSession(p, so, providers=["CPUExecutionProvider"])
for th in (1,4):
    a=mk(GL+"/onnx/model_quantized.onnx",th); b=mk("gliner_fasthead.onnx",th)
    ra=[a.run(None,f)[0] for f in feeds]; rb=[b.run(None,f)[0] for f in feeds]
    md=max(float(np.abs(x-y).max()) for x,y in zip(ra,rb))
    da=[decode(x,int(f["text_lengths"][0,0]),12,thr) for x,f in zip(ra,feeds)]
    db=[decode(x,int(f["text_lengths"][0,0]),12,thr) for x,f in zip(rb,feeds)]
    ta,_=timeit(lambda:[a.run(None,f) for f in feeds],reps=7); tb,_=timeit(lambda:[b.run(None,f) for f in feeds],reps=7)
    print(f"threads={th} orig={ta:.1f}ms fasthead={tb:.1f}ms speedup={ta/tb:.2f}x max|dlogit|={md:.4f} entities orig={sum(map(len,da))} new={sum(map(len,db))} identical={da==db}")
    if da!=db:
        for x,y in zip(da,db): print("  diff", set(x)^set(y))
