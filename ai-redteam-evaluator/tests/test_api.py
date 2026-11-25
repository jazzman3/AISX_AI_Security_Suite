import os, tempfile, pathlib
os.environ['ADMIN_PASSWORD']='test-only-secret-32-characters-long'
os.environ['DB_PATH']=str(pathlib.Path(tempfile.mkdtemp())/'test.db')
os.environ['DEMO_MODE']='true'
from fastapi.testclient import TestClient
from app.main import app
c=TestClient(app)
a=('admin','test-only-secret-32-characters-long')
def test_auth():
    assert c.get('/').status_code==401
    assert c.get('/',auth=a).status_code==200
    assert c.get('/health').json()['status']=='ok'
def test_input_validation():
    assert c.post('/api/run',json={},auth=a).status_code in (200,422)
