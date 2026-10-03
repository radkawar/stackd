# Reproduce protected service-linked role membership with uniquely owned IAM
# roles and an instance profile. Finally removes all owned resources.
# Usage: python3 internal/services/iam/testdata/service_linked_membership_probe.py
import datetime,json,re,subprocess,time,uuid
suffix='stackdprobe'+uuid.uuid4().hex[:8]
role='AWSServiceRoleForAutoScaling_'+suffix
ordinary=suffix+'ordinary'
profile=suffix+'profile'
observations=[]
created=[]
def call(op,*args):
 p=subprocess.run(['aws','iam',op,*args,'--output','json','--no-cli-pager'],capture_output=True,text=True)
 if p.returncode:
  m=re.search(r'An error occurred \(([^)]+)\)',p.stderr)
  return {'error':m.group(1) if m else 'CLIError','detail':p.stderr.strip()}
 return json.loads(p.stdout or '{}')
def check(result):
 if 'error' in result: raise RuntimeError(result)
 return result
try:
 check(call('create-role','--role-name',ordinary,'--assume-role-policy-document','{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"ec2.amazonaws.com"}}]}'))
 created.append('ordinary')
 observations.append({'name':'delete-ordinary-as-service-linked',**call('delete-service-linked-role','--role-name',ordinary)})
 check(call('create-service-linked-role','--aws-service-name','autoscaling.amazonaws.com','--custom-suffix',suffix))
 created.append('linked')
 check(call('create-instance-profile','--instance-profile-name',profile))
 created.append('profile')
 observations.append({'name':'add-to-instance-profile',**call('add-role-to-instance-profile','--instance-profile-name',profile,'--role-name',role)})
 observations.append({'name':'remove-from-instance-profile',**call('remove-role-from-instance-profile','--instance-profile-name',profile,'--role-name',role)})
finally:
 if 'profile' in created:
  current=call('get-instance-profile','--instance-profile-name',profile)
  for attached in current.get('InstanceProfile',{}).get('Roles',[]):check(call('remove-role-from-instance-profile','--instance-profile-name',profile,'--role-name',attached['RoleName']))
  check(call('delete-instance-profile','--instance-profile-name',profile))
 if 'linked' in created:
  deletion=check(call('delete-service-linked-role','--role-name',role))
  for i in range(120):
   status=check(call('get-service-linked-role-deletion-status','--deletion-task-id',deletion['DeletionTaskId']))
   if status['Status']=='SUCCEEDED': break
   if status['Status']=='FAILED': raise RuntimeError({'cleanup_failed':status,'role_name':role})
   time.sleep(2)
  else:raise RuntimeError({'cleanup_timeout':role})
 if 'ordinary' in created:
  result=call('delete-role','--role-name',ordinary)
  if result.get('error') not in (None,'NoSuchEntity'):raise RuntimeError({'cleanup_ordinary':result,'role':ordinary})
text=json.dumps({'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'observations':observations},indent=2).replace(suffix,'stackdprobe')
from pathlib import Path
Path(__file__).with_name('service_linked_membership_aws.json').write_text(text+'\n')
print(text)
