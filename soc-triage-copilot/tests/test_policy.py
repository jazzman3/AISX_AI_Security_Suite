from app.main import Alert,triage_alert
def test_high_priority():assert triage_alert(Alert(source='iam',category='credential_attack',asset_criticality=5,indicators=['known_bad_ip']))['priority']=='critical'
def test_low_priority():assert triage_alert(Alert(source='iam',category='informational',asset_criticality=1))['priority']=='low'
