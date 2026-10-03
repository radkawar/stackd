# Reproduce CreateServiceLinkedRole description field omission, using a
# uniquely suffixed owned Auto Scaling role. Finally deletes and polls the role.
# Usage: python3 internal/services/iam/testdata/service_linked_description_probe.py
import datetime,json,re,subprocess,time,uuid
suffix='stackdprobe'+uuid.uuid4().hex[:8]
name='AWSServiceRoleForAutoScaling_'+suffix
created=False
observations=[]
def call(op,*args):
 p=subprocess.run(['aws','iam',op,*args,'--output','json','--no-cli-pager'],capture_output=True,text=True)
 if p.returncode:raise RuntimeError(p.stderr)
 return json.loads(p.stdout or '{}')
try:
 output=call('create-service-linked-role','--aws-service-name','autoscaling.amazonaws.com','--custom-suffix',suffix,'--description','owned description probe')
 created=True
 observations.append({'name':'create-with-description',**output})
 observations.append({'name':'get-created-description',**call('get-role','--role-name',name)})
finally:
 if created:
  task=call('delete-service-linked-role','--role-name',name)
  for i in range(120):
   status=call('get-service-linked-role-deletion-status','--deletion-task-id',task['DeletionTaskId'])
   if status['Status']=='SUCCEEDED':break
   if status['Status']=='FAILED':raise RuntimeError({'cleanup_failed':status,'role':name})
   time.sleep(2)
  else:raise RuntimeError({'cleanup_timeout':name})
text=json.dumps({'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'observations':observations},indent=2).replace(suffix,'stackdprobe')
text=re.sub(r'arn:aws:iam::\d{12}:','arn:aws:iam::123456789012:',text)
from pathlib import Path
Path(__file__).with_name('service_linked_description_aws.json').write_text(text+'\n')
print(text)
