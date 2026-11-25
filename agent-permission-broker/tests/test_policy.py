from app.main import Action,decide
def test_denies_unlisted_tool():assert decide(Action(agent='leadbot',tool='shell.exec',resource='x'))['decision']=='deny'
def test_requires_approval():assert decide(Action(agent='leadbot',tool='crm.write',resource='x'))['decision']=='needs_approval'
def test_allows_read():assert decide(Action(agent='leadbot',tool='crm.read',resource='x'))['decision']=='allow'

def test_client_approval_flag_cannot_bypass():assert decide(Action(agent='leadbot',tool='crm.write',resource='x',approved=True))['decision']=='needs_approval'
