from app.common import app,auth,record,db,BaseModel,Field,Depends,HTTPException
class Action(BaseModel):
    agent:str=Field(min_length=1,max_length=80)
    tool:str=Field(min_length=1,max_length=100)
    resource:str=Field(min_length=1,max_length=140)
    approved:bool=False
POLICY={'leadbot':{'crm.read':False,'crm.write':True},'supportbot':{'ticket.read':False,'ticket.reply':True},'researchbot':{'web.search':False}}
def decide(x):
    granted=POLICY.get(x.agent,{})
    if x.tool not in granted:return {'decision':'deny','reason':'tool not in allowlist'}
    if granted[x.tool]:return {'decision':'needs_approval','reason':'separate server-side approval is required'}
    return {'decision':'allow','reason':'least privilege allowlist satisfied','note':'authorization only; no external tool executed'}
@app.post('/api/authorize')
def authorize(x:Action,user=Depends(auth)):
    out=decide(x)
    if out['decision']=='needs_approval':
        with db() as c:
            c.execute('CREATE TABLE IF NOT EXISTS approvals (agent TEXT,tool TEXT,resource TEXT,used INTEGER DEFAULT 0)')
            row=c.execute('SELECT rowid FROM approvals WHERE agent=? AND tool=? AND resource=? AND used=0 ORDER BY rowid DESC LIMIT 1',(x.agent,x.tool,x.resource)).fetchone()
            if row:
                c.execute('UPDATE approvals SET used=1 WHERE rowid=?',(row[0],));c.commit()
                out={'decision':'allow','reason':'single-use approval consumed; no tool executed'}
    record(user,'authorize','blocked' if out['decision']=='deny' else 'medium',x.agent,{'tool':x.tool,'resource':x.resource,'decision':out['decision']})
    return out

@app.post('/api/approve')
def approve_action(x:Action,user=Depends(auth)):
    if decide(x)['decision']!='needs_approval':
        raise HTTPException(status_code=400,detail='Only listed high-impact actions require approval')
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS approvals (agent TEXT,tool TEXT,resource TEXT,used INTEGER DEFAULT 0)')
        c.execute('INSERT INTO approvals(agent,tool,resource) VALUES(?,?,?)',(x.agent,x.tool,x.resource));c.commit()
    record(user,'human_approval','medium',x.agent,{'tool':x.tool,'resource':x.resource})
    return {'approved':True,'scope':'single-use','note':'Separate review endpoint; replace single-admin demo authentication with enterprise RBAC before deployment'}
