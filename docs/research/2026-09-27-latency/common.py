import re, time, numpy as np, os
from tokenizers import Tokenizer
M = os.environ.get("INUMAKI_MODELS_DIR", os.path.expanduser("~/Library/Application Support/inumaki/models"))
GL = M+"/gliner-x-small"; MB = M+"/mbert-ner-hrl"
LABELS = ["person","name","full name","street address","city","organization","phone number"]
WORD = re.compile(r"\w+(?:[-_]\w+)*|\S")
def chunks(text, max_bytes=1530, overlap=200):
    b = text.encode(); out=[]; start=0
    while True:
        if start+max_bytes >= len(b): out.append(b[start:].decode()); return out
        win = b[start:start+max_bytes]; cut = win.rfind(b" ", len(win)//2)
        cut = start + (cut+1 if cut>0 else len(win))
        while True:
            try: b[start:cut].decode(); break
            except UnicodeDecodeError: cut-=1
        out.append(b[start:cut].decode())
        nxt = b.find(b" ", max(cut-overlap, start+1))
        start = nxt+1 if 0 <= nxt < cut else cut
class Gliner:
    def __init__(self, tok_path=GL+"/tokenizer.json", max_width=12):
        self.tok = Tokenizer.from_file(tok_path); self.tok.no_truncation(); self.tok.no_padding(); self.mw=max_width
    def enc_word(self, w): return self.tok.encode(w, add_special_tokens=False).ids
    def prep(self, text, labels=LABELS):
        lp = []
        for l in labels: lp += [self.enc_word("<<ENT>>"), self.enc_word(l)]
        lp.append(self.enc_word("<<SEP>>"))
        words = [m.group() for m in WORD.finditer(text)]
        tp = [ids for ids in (self.enc_word(w) for w in words) if ids]
        ids=[1]; [ids.extend(w) for w in lp]; wm=[0]*len(ids)
        for i,w in enumerate(tp):
            for j,t in enumerate(w): ids.append(t); wm.append(i+1 if j==0 else 0)
        ids.append(2); wm.append(0)
        n=len(tp); mw=self.mw
        si=np.zeros((1,n*mw,2),np.int64); sm=np.zeros((1,n*mw),bool)
        for s in range(n):
            for w in range(min(mw,n-s)): si[0,s*mw+w]=(s,s+w); sm[0,s*mw+w]=True
        L=len(ids)
        return {"input_ids":np.array([ids],np.int64),"attention_mask":np.ones((1,L),np.int64),
                "words_mask":np.array([wm],np.int64),"text_lengths":np.array([[n]],np.int64),
                "span_idx":si,"span_mask":sm}
class Mbert:
    def __init__(self):
        self.tok = Tokenizer.from_file(MB+"/tokenizer.json"); self.tok.no_truncation(); self.tok.no_padding()
    def prep(self, text):
        e=self.tok.encode(text); a=lambda v: np.array([v],np.int64)
        return {"input_ids":a(e.ids),"attention_mask":a(e.attention_mask),"token_type_ids":a(e.type_ids)}
def timeit(f, reps=10, warm=2):
    for _ in range(warm): f()
    ts=[]
    for _ in range(reps):
        t=time.perf_counter(); f(); ts.append((time.perf_counter()-t)*1000)
    ts.sort(); return ts[len(ts)//2], ts[0]
