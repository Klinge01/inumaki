import numpy as np
def decode(logits, n, mw, thr):
    L = logits[0]; out=[]
    sc = 1/(1+np.exp(-L))
    for s in range(n):
        for w in range(min(mw, n-s)):
            for c in range(L.shape[2]):
                if sc[s,w,c] >= thr[c]: out.append((s,s+w,c,float(sc[s,w,c])))
    out.sort(key=lambda x:-x[3]); acc=[]
    for c in out:
        if all(c[1] < a[0] or a[1] < c[0] for a in acc): acc.append(c)
    return sorted((a[0],a[1],a[2]) for a in acc)
