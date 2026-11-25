from app.common import app,auth,record,BaseModel,Field,Depends,db
class Asset(BaseModel):
    name:str=Field(min_length=2,max_length=80)
    owner:str=Field(min_length=2,max_length=80)
    public_endpoint:bool=False
    sensitive_data:bool=False
    logging:bool=True
    approval_gate:bool=True
    approved_vendor:bool=True
def assess(x):
    f=[]
    if x.public_endpoint and x.sensitive_data:f.append('public_sensitive_ai_endpoint')
    if not x.logging:f.append('missing_audit_logging')
    if not x.approval_gate:f.append('no_human_approval_gate')
    if not x.approved_vendor:f.append('unapproved_ai_vendor')
    score=min(100, len(f)*25)
    return {'risk_score':score,'risk':'high' if score>=50 else 'medium' if score else 'low','findings':f,'standard':'AISX example posture policy v1'}
@app.post('/api/assets')
def add(x:Asset,user=Depends(auth)):
    result=assess(x)
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY,name TEXT UNIQUE,owner TEXT,risk INTEGER,findings TEXT)')
        c.execute('INSERT INTO assets(name,owner,risk,findings) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,risk=excluded.risk,findings=excluded.findings',(x.name,x.owner,result['risk_score'],str(result['findings'])))
        c.commit()
    record(user,'inventory',result['risk'],x.name,{'score':result['risk_score'],'findings':result['findings']})
    return result
@app.get('/api/assets')
def list_assets(user=Depends(auth)):
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY,name TEXT UNIQUE,owner TEXT,risk INTEGER,findings TEXT)')
        rows=c.execute('SELECT name,owner,risk,findings FROM assets').fetchall()
    return {'assets':[{'name':a,'owner':b,'risk_score':c,'findings':d} for a,b,c,d in rows]}
