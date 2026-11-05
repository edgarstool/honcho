import sys,os,json,tempfile,subprocess,time,secrets,base64,hashlib,ssl
from pathlib import Path
from contextlib import ExitStack
from datetime import datetime,timedelta,timezone
from urllib.parse import parse_qs,urlparse
sys.path.insert(0,'/srv/edgar/workspaces/projects/edgar-auth-server-honcho-stage')
from examples.protocol_demo import private_key,listener,serve,hidden
from edgar_auth.app import Config,create_app
from argon2 import PasswordHasher
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization,hashes
from ipaddress import ip_address
import httpx
stage=Path('/home/edgar/EDGAR-OPS/staging/edg15-clean-tokenizer-20261106')
backend=os.environ.get('EDG15_TEST_BACKEND','http://172.19.0.3:8000')
mcp='http://127.0.0.1:18333/mcp'
checks={}
with tempfile.TemporaryDirectory(prefix='edg15-real-') as tmp,ExitStack() as stack:
 root=Path(tmp); key,pem=private_key(); now=datetime.now(timezone.utc)
 name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'EDG15 isolated')])
 cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address('127.0.0.1'))]),False).add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(key,hashes.SHA256()))
 cf=root/'tls.crt'; kf=root/'tls.pem';cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM));kf.write_bytes(pem);kf.chmod(0o600)
 sock=listener();issuer='https://127.0.0.1:'+str(sock.getsockname()[1])
 app=create_app(Config(issuer=issuer,resource=mcp,database=str(root/'as.db'),signing_key=private_key()[1].decode(),dcr_enabled=True))
 pw=secrets.token_urlsafe(20);secret=secrets.token_urlsafe(32)
 app.state.store.add_user('edg15-test',PasswordHasher().hash(pw))
 app.state.store.register_client('resource',['https://stage.example/callback'],'client_secret_basic',secret)
 stack.enter_context(serve(app,sock,cf,kf))
 a=stack.enter_context(httpx.Client(base_url=issuer,verify=ssl.create_default_context(cafile=str(cf)),trust_env=False,follow_redirects=False,timeout=15))
 client=a.post('/register',json={'redirect_uris':['https://stage.example/callback'],'token_endpoint_auth_method':'none'});assert client.status_code==201,client.text
 cid=client.json()['client_id'];checks['DCR']=True
 def token(scope):
  verifier=secrets.token_urlsafe(48);challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
  r=a.get('/authorize',params={'client_id':cid,'redirect_uri':'https://stage.example/callback','response_type':'code','scope':scope,'resource':mcp,'state':'stage','code_challenge':challenge,'code_challenge_method':'S256'})
  assert r.status_code==303,r.text
  loc=r.headers['location']
  if loc.startswith('/login?'):
   r=a.post('/login',data={**hidden(a.get(loc).text),'username':'edg15-test','password':pw});assert r.status_code==303,r.text;loc=r.headers['location']
  r=a.post('/consent',data={**hidden(a.get(loc).text),'decision':'approve'})
  code=parse_qs(urlparse(r.headers['location']).query)['code'][0]
  r=a.post('/token',data={'grant_type':'authorization_code','code':code,'redirect_uri':'https://stage.example/callback','code_verifier':verifier,'client_id':cid,'resource':mcp});assert r.status_code==200,r.text
  return r.json()['access_token']
 ro=token('mcp mcp:read');rw=token('mcp mcp:read mcp:write');checks['PKCE_LOGIN_CONSENT_TOKEN']=True
 env={**os.environ,'HOST':'127.0.0.1','PORT':'18333','MCP_OAUTH_ENABLED':'1','MCP_OAUTH_ISSUER':issuer,'MCP_OAUTH_AUDIENCE':mcp,'MCP_OAUTH_JWKS_URL':issuer+'/jwks.json','MCP_OAUTH_REQUIRED_SCOPE':'mcp','MCP_OAUTH_MAPPING':json.dumps({'mappings':[{'sub':'edg15-test','workspace_id':'edg15-e2e','scopes':['mcp','mcp:read','mcp:write']}]}),'MCP_OAUTH_INTROSPECT_URL':issuer+'/introspect','MCP_OAUTH_INTROSPECT_CLIENT_ID':'resource','MCP_OAUTH_INTROSPECT_CLIENT_SECRET':secret,'HONCHO_API_KEY':'synthetic-backend-noauth','HONCHO_API_URL':backend,'NODE_EXTRA_CA_CERTS':str(cf),'SSL_CERT_FILE':str(cf)}
 log=open(stage/'real-mcp.log','w');stack.callback(log.close)
 proc=subprocess.Popen(['/home/edgar/.bun/bin/bun','run','src/http.ts'],cwd='/srv/edgar/workspaces/projects/edg15-honcho-oauth-stage-20261106/mcp',env=env,stdout=log,stderr=log)
 stack.callback(lambda:proc.wait(timeout=10));stack.callback(proc.terminate)
 b=stack.enter_context(httpx.Client(trust_env=False,timeout=20))
 for _ in range(50):
  try:
   if b.get('http://127.0.0.1:18333/health').status_code==200:break
  except httpx.ConnectError:pass
  time.sleep(.2)
 def rpc(tok,method,params,sid=None):
  headers={'Authorization':'Bearer '+tok,'Accept':'application/json, text/event-stream','Content-Type':'application/json'}
  if sid:headers['mcp-session-id']=sid
  r=b.post(mcp,headers=headers,json={'jsonrpc':'2.0','id':1,'method':method,'params':params})
  if r.status_code!=200:return r,None
  if 'text/event-stream' in r.headers.get('content-type',''):
   body=json.loads(next(l[6:] for l in r.text.splitlines() if l.startswith('data: ')))
  else:body=r.json()
  return r,body
 def init(tok):
  r,j=rpc(tok,'initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'edg15-real','version':'1'}});assert r.status_code==200,(r.status_code,r.text);return r.headers['mcp-session-id']
 rs=init(ro);ws=init(rw);checks['MCP_INITIALIZE']=True
 r,j=rpc(ro,'tools/list',{},rs);assert r.status_code==200,j
 names=[t['name'] for t in j['result']['tools']];assert 'create_peer' not in names and 'list_peers' in names
 checks['READ_TOOL_FILTER']=True
 r,j=rpc(rw,'tools/call',{'name':'create_peer','arguments':{'workspace_id':'edg15-e2e','peer_id':'stage-marker'}},ws)
 assert r.status_code==200 and not j.get('error') and not j.get('result',{}).get('isError'),j
 checks['REAL_HONCHO_WRITE']=True
 r,j=rpc(ro,'tools/call',{'name':'list_peers','arguments':{'workspace_id':'edg15-e2e'}},rs)
 assert 'stage-marker' in json.dumps(j),j;checks['REAL_HONCHO_READ']=True
 r,j=rpc(ro,'tools/call',{'name':'create_peer','arguments':{'peer_id':'denied'}},rs)
 assert j.get('error') or j.get('result',{}).get('isError'),j;checks['READ_WRITE_DENY']=True
 r,j=rpc(rw,'tools/call',{'name':'list_peers','arguments':{'workspace_id':'foreign-workspace'}},ws)
 assert j.get('error') or j.get('result',{}).get('isError'),j;checks['CROSS_WORKSPACE_DENY']=True
 r=a.post('/revoke',auth=(cid,''),data={'token':rw,'client_id':cid})
 if r.status_code!=200:r=a.post('/revoke',data={'token':rw,'client_id':cid})
 assert r.status_code==200,r.text
 r,j=rpc(rw,'tools/list',{},ws);assert r.status_code==401,(r.status_code,r.text);checks['REVOKED_TOKEN_401']=True
 print(json.dumps(checks,indent=2),flush=True)
 (stage/'real-e2e-result.json').write_text(json.dumps(checks,indent=2))
