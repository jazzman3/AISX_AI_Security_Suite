import re
from app.common import app,auth,record,BaseModel,Field,Depends
class Inspect(BaseModel):
    text:str=Field(min_length=1,max_length=12000)
    direction:str='input'
PATTERNS={'prompt_injection':r'(?i)(ignore (all |the )?(previous|prior) instructions|reveal (the )?(system prompt|hidden instructions)|developer mode|override (your |the )?rules)', 'secret':r'(?i)(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)', 'email':r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 'ssn':r'\b\d{3}-\d{2}-\d{4}\b'}
def inspect_text(s):
    matches=[k for k,p in PATTERNS.items() if re.search(p,s)]
    return {'decision':'block' if matches else 'allow','risk': 'high' if matches else 'low','findings':matches,'policy':'regex_rules_v1','note':'Heuristic control: not comprehensive protection'}
@app.post('/api/inspect')
def inspect(x:Inspect,user=Depends(auth)):
    if x.direction not in ('input','output'):return {'decision':'block','findings':['invalid_direction']}
    out=inspect_text(x.text)
    record(user,'inspect','blocked' if out['decision']=='block' else 'low',x.direction,{'findings':out['findings'],'length':len(x.text)})
    return out
