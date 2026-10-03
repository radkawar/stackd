# Reproduce ordinary role response fields using a uniquely named, tagged IAM
# role with an AWS-managed permissions boundary. The finally block deletes it.
# Usage: python3 internal/services/iam/testdata/role_wire_probe.py
import datetime,json,re,subprocess,uuid
name='stackdprobe'+uuid.uuid4().hex[:10]
path='/'+name+'/'
observations=[]
def call(op,*args):
 p=subprocess.run(['aws','iam',op,*args,'--output','json','--no-cli-pager'],capture_output=True,text=True)
 if p.returncode:raise RuntimeError(p.stderr)
 return json.loads(p.stdout or '{}')
created=False
try:
 result=call('create-role','--role-name',name,'--path',path,'--assume-role-policy-document','{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"ec2.amazonaws.com"}}]}','--tags','Key=team,Value=probe','--permissions-boundary','arn:aws:iam::aws:policy/ReadOnlyAccess','--description','created-description')
 created=True
 observations.append({'name':'create',**result})
 observations.append({'name':'get',**call('get-role','--role-name',name)})
 observations.append({'name':'list',**call('list-roles','--path-prefix',path)})
 observations.append({'name':'update-description',**call('update-role-description','--role-name',name,'--description','updated-description')})
 observations.append({'name':'get-after-description',**call('get-role','--role-name',name)})
finally:
 if created:
  call('delete-role-permissions-boundary','--role-name',name)
  call('delete-role','--role-name',name)
text=json.dumps({'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':'Owned tagged ordinary IAM role with ReadOnlyAccess permissions boundary, deleted successfully.','observations':observations},indent=2).replace(name,'stackdprobe')
text=re.sub(r'arn:aws:iam::\d{12}:','arn:aws:iam::123456789012:',text)
from pathlib import Path
Path(__file__).with_name('role_wire_aws.json').write_text(text+'\n')
print(text)
