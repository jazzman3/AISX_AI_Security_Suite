from app.common import app,auth,record,BaseModel,Field,Depends
class Alert(BaseModel):
    source:str=Field(min_length=2,max_length=80)
    category:str=Field(min_length=2,max_length=80)
    asset_criticality:int=Field(ge=1,le=5)
    indicators:list[str]=Field(default_factory=list,max_length=12)
    summary:str=Field(max_length=250,default='')
WEIGHTS={'impossible_travel':35,'credential_attack':45,'malware':50,'policy_violation':20,'new_device':10,'failed_logins':15,'mfa_disabled':20,'known_bad_ip':30}
def triage_alert(x):
    score=min(100, 5*x.asset_criticality+WEIGHTS.get(x.category,10)+sum(WEIGHTS.get(i,0) for i in set(x.indicators)))
    return {'score':score,'priority':'critical' if score>=85 else 'high' if score>=65 else 'medium' if score>=35 else 'low','recommended_action':'Escalate for analyst validation' if score>=65 else 'Review in standard queue','explanation':{'asset_criticality':x.asset_criticality,'category':x.category,'indicators':list(set(x.indicators))},'note':'Decision support only; no auto-containment'}
@app.post('/api/triage')
def triage(x:Alert,user=Depends(auth)):
    result=triage_alert(x)
    record(user,'triage',result['priority'],x.category,{'score':result['score'],'source':x.source,'indicators':x.indicators})
    return result
