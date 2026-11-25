from app.main import Asset,assess
def test_high_risk_asset():assert assess(Asset(name='Unsafe Agent',owner='Sales',public_endpoint=True,sensitive_data=True,logging=False))['risk']=='high'
def test_safe_asset():assert assess(Asset(name='Internal Agent',owner='IT'))['risk']=='low'
