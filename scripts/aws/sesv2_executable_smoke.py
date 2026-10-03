#!/usr/bin/env python3
"""Actual local CLI/SDK SES and Cognito MIME capture, authority and restart proof."""
import argparse
from datetime import datetime, timezone
import email
import email.policy
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import time
import urllib.request
import uuid
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from aws_cli import run, result
from cloudtrail_events import collect_s3
from stackd_process import StackdProcess

parser=argparse.ArgumentParser()
parser.add_argument('--binary',required=True)
parser.add_argument('--state-directory',required=True)
args=parser.parse_args()
state=Path(args.state_directory).resolve();state.mkdir(parents=True,exist_ok=True)
database=state/'email.sqlite'
if database.exists():raise SystemExit('refusing existing smoke state')
with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
endpoint=f'http://127.0.0.1:{port}'
account='123456789012'
env={k:v for k,v in os.environ.items() if not k.startswith('AWS_')}
env.update(AWS_ACCESS_KEY_ID='test',AWS_SECRET_ACCESS_KEY='test',AWS_DEFAULT_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',AWS_PAGER='')
controller=StackdProcess(state)
report={'endpoint':endpoint,'observations':{},'cleanup':{},'controllers':controller.runs}

def require(condition,message):
    if not condition:raise AssertionError(message)
def client(service,key='test',secret='test',region='us-east-1'):
    return boto3.client(service,endpoint_url=endpoint,region_name=region,aws_access_key_id=key,aws_secret_access_key=secret,config=Config(retries={'total_max_attempts':1},connect_timeout=3,read_timeout=30))
def start():
    command=[str(Path(args.binary).resolve()),'-listen',f'127.0.0.1:{port}','-public-endpoint',endpoint,'-account-id',account,'-database',str(database),'-clock-start',datetime.now(timezone.utc).isoformat()]
    controller.start(command,endpoint,environment=env,timeout=30)
def drain():
    request=urllib.request.Request(endpoint+'/_stackd/jobs/drain?limit=1024',data=b'',headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=10) as response:response.read()
def messages():
    drain();out=[]
    for path in Path(str(database)+'.ses').rglob('*.eml'):
        out.append((path,email.message_from_bytes(path.read_bytes(),policy=email.policy.default)))
    return out
def text(message):
    body=message.get_body(preferencelist=('plain','html'))
    return body.get_content() if body else ''
def find(subject,recipient=None):
    rows=[(p,m) for p,m in messages() if str(m['Subject'])==subject and (recipient is None or str(m['To'])==recipient)]
    require(len(rows)==1,f'expected one {subject} capture, found {len(rows)}')
    return rows[0]
def denied(fn,codes):
    try:fn()
    except ClientError as e:
        code=e.response['Error']['Code'];require(code in codes,f'unexpected denial {code}');return code
    raise AssertionError('expected rejection')
def advance(duration):
    request=urllib.request.Request(endpoint+'/_stackd/clock',data=json.dumps({'advance':duration}).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=10) as response:response.read()
def deletion_status(task):
    for attempt in range(30):
        drain();deletion=client('iam').get_service_linked_role_deletion_status(DeletionTaskId=task)
        if deletion['Status']!='IN_PROGRESS':return deletion
        advance('1s')
    raise AssertionError(f'role deletion did not terminate: {deletion}')

owned=[]
try:
    start();ses=client('sesv2');cognito=client('cognito-idp');iam=client('iam')
    s3=client('s3');trail=client('cloudtrail');bucket='mail-audit-'+uuid.uuid4().hex[:12];trail_name='mail-audit'
    s3.create_bucket(Bucket=bucket);owned.append(('bucket',bucket))
    trail_arn=f'arn:aws:cloudtrail:us-east-1:{account}:trail/{trail_name}'
    s3.put_bucket_policy(Bucket=bucket,Policy=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'cloudtrail.amazonaws.com'},'Action':'s3:GetBucketAcl','Resource':f'arn:aws:s3:::{bucket}','Condition':{'StringEquals':{'aws:SourceArn':trail_arn}}},{'Effect':'Allow','Principal':{'Service':'cloudtrail.amazonaws.com'},'Action':'s3:PutObject','Resource':f'arn:aws:s3:::{bucket}/AWSLogs/{account}/*','Condition':{'StringEquals':{'aws:SourceArn':trail_arn,'s3:x-amz-acl':'bucket-owner-full-control'}}}]}))
    trail.create_trail(Name=trail_name,S3BucketName=bucket);owned.append(('trail',trail_name))
    selectors=[{'Name':'Management','FieldSelectors':[{'Field':'eventCategory','Equals':['Management']}]}]
    selectors.extend({'Name':kind,'FieldSelectors':[{'Field':'eventCategory','Equals':['Data']},{'Field':'resources.type','Equals':[kind]}]} for kind in ['AWS::SES::EmailIdentity','AWS::SES::Template','AWS::SES::ConfigurationSet'])
    trail.put_event_selectors(TrailName=trail_name,AdvancedEventSelectors=selectors)
    trail.start_logging(Name=trail_name)
    sender='sender@example.invalid'
    identity_response=ses.create_email_identity(EmailIdentity=sender,Tags=[{'Key':'application','Value':'mail-smoke'}]);owned.append(('identity',sender))
    simple={'FromEmailAddress':sender,'Destination':{'ToAddresses':['success@simulator.amazonses.com']},'Content':{'Simple':{'Subject':{'Data':'CLI simple café'},'Body':{'Text':{'Data':'readable CLI text'},'Html':{'Data':'<p>readable HTML</p>'}}}}}
    report['observations']['unverified']=denied(lambda:ses.send_email(**simple),{'MessageRejected'})
    _,verification=find('Amazon SES Email Address Verification Request')
    url=re.search(r'http://[^\s]+',text(verification)).group(0)
    with urllib.request.urlopen(url) as response:require(response.status==200,'verification link failed')
    ses.create_configuration_set(ConfigurationSetName='inherited');owned.append(('configuration','inherited'))
    ses.put_email_identity_configuration_set_attributes(EmailIdentity=sender,ConfigurationSetName='inherited')
    sent=result(run('sesv2','send-email',simple,env,options=['--endpoint-url',endpoint,'--cli-binary-format','raw-in-base64-out']))
    require(sent['code']=='Success',str(sent));report['observations']['cli_simple_id']=sent['output']['MessageId']
    path,mime=find('CLI simple café');require(text(mime)=='readable CLI text','simple MIME content lost');digest=hashlib.sha256(path.read_bytes()).hexdigest()
    raw=b'From: sender@example.invalid\r\nTo: success@simulator.amazonses.com\r\nBcc: complaint@simulator.amazonses.com\r\nSubject: SDK raw\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nraw SDK body\r\n'
    raw_response=ses.send_email(Content={'Raw':{'Data':raw}});_,raw_message=find('SDK raw');require(raw_message['Bcc'] is None and text(raw_message).strip()=='raw SDK body','raw MIME or BCC privacy lost')
    ses.create_email_template(TemplateName='greeting',TemplateContent={'Subject':'Template {{name}}','Text':'Hello {{name}}, code {{code}}','Html':'<b>{{name}}</b>'});owned.append(('template','greeting'))
    template_response=ses.send_email(FromEmailAddress=sender,Destination=simple['Destination'],Content={'Template':{'TemplateName':'greeting','TemplateData':json.dumps({'name':'SDK','code':'654321'})}})
    _,templated=find('Template SDK');require('654321' in text(templated),'template failed to render')
    bulk=ses.send_bulk_email(FromEmailAddress=sender,DefaultContent={'Template':{'TemplateName':'greeting','TemplateData':'{"name":"Bulk","code":"123456"}'}},BulkEmailEntries=[{'Destination':simple['Destination']},{'Destination':{'ToAddresses':['unverified@example.invalid']}},{'Destination':simple['Destination'],'ReplacementEmailContent':{'ReplacementTemplate':{'ReplacementTemplateData':'{"name":"Missing"}'}}}])
    statuses=[v['Status'] for v in bulk['BulkEmailEntryResults']];require(statuses==['SUCCESS','MESSAGE_REJECTED','FAILED'],str(statuses));report['observations']['bulk']=statuses
    for invalid in [b'malformed',raw.replace(b'raw SDK body',b'x'*999)]:denied(lambda:ses.send_email(Content={'Raw':{'Data':invalid}}),{'BadRequestException'})
    report['observations']['region_isolation']=denied(lambda:client('sesv2',region='us-west-2').send_email(**simple),{'MessageRejected'})
    iam.create_user(UserName='mail-denied');owned.append(('user','mail-denied'));key=iam.create_access_key(UserName='mail-denied')['AccessKey']
    report['observations']['iam_denial']=denied(lambda:client('sesv2',key['AccessKeyId'],key['SecretAccessKey']).send_email(**simple),{'AccessDeniedException'})
    scoped={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'ses:SendEmail','Resource':'*','Condition':{'StringEquals':{'aws:ResourceTag/application':'mail-smoke','ses:ApiVersion':'2'}}}]}
    iam.put_user_policy(UserName='mail-denied',PolicyName='identity-only',PolicyDocument=json.dumps(scoped))
    report['observations']['configuration_tag_isolation']=denied(lambda:client('sesv2',key['AccessKeyId'],key['SecretAccessKey']).send_email(**simple),{'AccessDeniedException'})
    report['observations']['bulk_iam_denial']=denied(lambda:client('sesv2',key['AccessKeyId'],key['SecretAccessKey']).send_bulk_email(FromEmailAddress=sender,DefaultContent={'Template':{'TemplateName':'greeting','TemplateData':'{"name":"Denied","code":"000000"}'}},BulkEmailEntries=[{'Destination':simple['Destination']}]),{'AccessDeniedException'})
    del scoped['Statement'][0]['Condition']['StringEquals']['aws:ResourceTag/application']
    iam.put_user_policy(UserName='mail-denied',PolicyName='identity-only',PolicyDocument=json.dumps(scoped))
    versioned=json.loads(json.dumps(simple));versioned['Content']['Simple']['Subject']['Data']='Version-scoped IAM'
    client('sesv2',key['AccessKeyId'],key['SecretAccessKey']).send_email(**versioned)
    _,version_mail=find('Version-scoped IAM');require(text(version_mail)=='readable CLI text','version-scoped send was not captured')
    report['observations']['api_version_condition']={'allowed':'2','rejected':{}}
    for other_version in ('1','2019-09-27'):
        scoped['Statement'][0]['Condition']['StringEquals']['ses:ApiVersion']=other_version
        iam.put_user_policy(UserName='mail-denied',PolicyName='identity-only',PolicyDocument=json.dumps(scoped))
        report['observations']['api_version_condition']['rejected'][other_version]=denied(lambda:client('sesv2',key['AccessKeyId'],key['SecretAccessKey']).send_email(**versioned),{'AccessDeniedException'})
    iam.delete_user_policy(UserName='mail-denied',PolicyName='identity-only')
    pool=cognito.create_user_pool(PoolName='mail-workflow',AutoVerifiedAttributes=['email'])['UserPool'];owned.append(('pool',pool['Id']))
    app=cognito.create_user_pool_client(UserPoolId=pool['Id'],ClientName='application',ExplicitAuthFlows=['ALLOW_USER_PASSWORD_AUTH','ALLOW_REFRESH_TOKEN_AUTH'])['UserPoolClient']
    cognito.sign_up(ClientId=app['ClientId'],Username='alice',Password='FirstPassword1!',UserAttributes=[{'Name':'email','Value':'alice@example.invalid'}])
    _,verification=find('Your verification code');code=re.search(r'\d{6}',text(verification)).group(0)
    denied(lambda:cognito.confirm_sign_up(ClientId=app['ClientId'],Username='alice',ConfirmationCode='bad-code'),{'CodeMismatchException'})
    controller.stop();start();require(hashlib.sha256(path.read_bytes()).hexdigest()==digest,'capture changed across restart')
    cognito.delete_user_pool_client(UserPoolId=pool['Id'],ClientId=app['ClientId'])
    app=cognito.create_user_pool_client(UserPoolId=pool['Id'],ClientName='replacement',ExplicitAuthFlows=['ALLOW_USER_PASSWORD_AUTH','ALLOW_REFRESH_TOKEN_AUTH'])['UserPoolClient']
    cognito.confirm_sign_up(ClientId=app['ClientId'],Username='alice',ConfirmationCode=code)
    cognito.delete_user_pool_client(UserPoolId=pool['Id'],ClientId=app['ClientId'])
    cognito.admin_reset_user_password(UserPoolId=pool['Id'],Username='alice')
    app=cognito.create_user_pool_client(UserPoolId=pool['Id'],ClientName='after-admin-reset',PreventUserExistenceErrors='ENABLED',ExplicitAuthFlows=['ALLOW_USER_PASSWORD_AUTH','ALLOW_REFRESH_TOKEN_AUTH'])['UserPoolClient']
    _,reset=find('Your password reset code');code=re.search(r'\d{6}',text(reset)).group(0)
    cognito.confirm_forgot_password(ClientId=app['ClientId'],Username='alice',ConfirmationCode=code,Password='SecondPassword2!')
    tokens=cognito.initiate_auth(ClientId=app['ClientId'],AuthFlow='USER_PASSWORD_AUTH',AuthParameters={'USERNAME':'alice','PASSWORD':'SecondPassword2!'})['AuthenticationResult'];require(tokens['AccessToken'],'password transition failed')
    cognito.admin_update_user_attributes(UserPoolId=pool['Id'],Username='alice',UserAttributes=[{'Name':'email','Value':'alice-updated@example.invalid'}])
    _,update_mail=find('Your verification code','alice-updated@example.invalid');update_code=re.search(r'\d{6}',text(update_mail)).group(0)
    cognito.verify_user_attribute(AccessToken=tokens['AccessToken'],AttributeName='email',Code=update_code)
    attrs={v['Name']:v['Value'] for v in cognito.get_user(AccessToken=tokens['AccessToken'])['UserAttributes']}
    require(attrs['email_verified']=='true' and attrs['email']=='alice-updated@example.invalid','admin email update verification failed')
    before_private={p for p,_ in messages()}
    private=cognito.forgot_password(ClientId=app['ClientId'],Username='missing@example.invalid')
    require(private['CodeDeliveryDetails']['DeliveryMedium']=='EMAIL','existence protection response missing')
    denied(lambda:cognito.confirm_forgot_password(ClientId=app['ClientId'],Username='missing@example.invalid',ConfirmationCode='123456',Password='NeverAccepted1!'),{'CodeMismatchException'})
    require({p for p,_ in messages()}==before_private,'existence protection emitted phantom email')
    report['observations']['admin_attribute_verification_and_existence_protection']=True
    cognito.update_user_pool(UserPoolId=pool['Id'],AutoVerifiedAttributes=['email'],AccountRecoverySetting={'RecoveryMechanisms':[{'Name':'verified_phone_number','Priority':1},{'Name':'verified_email','Priority':2}]})
    cognito.admin_update_user_attributes(UserPoolId=pool['Id'],Username='alice',UserAttributes=[{'Name':'phone_number','Value':'+12025550123'},{'Name':'phone_number_verified','Value':'true'}])
    denied(lambda:cognito.forgot_password(ClientId=app['ClientId'],Username='alice'),{'InvalidParameterException'})
    require({p for p,_ in messages()}==before_private,'SMS priority silently fell back to email')
    report['observations']['unsupported_sms_priority_preserved']=True
    developer=cognito.create_user_pool(PoolName='developer-mail',AutoVerifiedAttributes=['email'],EmailConfiguration={'EmailSendingAccount':'DEVELOPER','SourceArn':f'arn:aws:ses:us-east-1:{account}:identity/{sender}','From':sender})['UserPool'];owned.append(('pool',developer['Id']))
    owned.insert(len(owned)-1,('linked-role','AWSServiceRoleForAmazonCognitoIdpEmailService'))
    developer_app=cognito.create_user_pool_client(UserPoolId=developer['Id'],ClientName='developer-app')['UserPoolClient']
    denied(lambda:cognito.sign_up(ClientId=developer_app['ClientId'],Username='rejected',Password='FirstPassword1!',UserAttributes=[{'Name':'email','Value':'unverified@example.invalid'}]),{'CodeDeliveryFailureException'})
    denied(lambda:cognito.admin_get_user(UserPoolId=developer['Id'],Username='rejected'),{'UserNotFoundException'})
    cognito.sign_up(ClientId=developer_app['ClientId'],Username='accepted',Password='FirstPassword1!',UserAttributes=[{'Name':'email','Value':'success@simulator.amazonses.com'}])
    drain();report['observations']['developer_role_and_transaction_rollback']=True
    protected=deletion_status(iam.delete_service_linked_role(RoleName='AWSServiceRoleForAmazonCognitoIdpEmailService')['DeletionTaskId'])
    require(protected['Status']=='FAILED' and any(developer['Arn'] in row['Resources'] for row in protected['Reason']['RoleUsageList']),'active developer pool did not protect email role')
    report['observations']['developer_role_dependency']=protected
    requests={identity_response['ResponseMetadata']['RequestId']:'create-identity',template_response['ResponseMetadata']['RequestId']:'template-send',raw_response['ResponseMetadata']['RequestId']:'raw-send'}
    advance('10m')
    drain()
    collected=collect_s3(lambda p:s3.list_objects_v2(**p),lambda p:s3.get_object(**p),requests,bucket=bucket,rounds=1)
    report['observations']['audit_collection']=collected
    require(not collected['missing_calls'],str(collected['missing_calls']))
    events={row['call_label']:row['event'] for row in collected['events'] if row['call_label']}
    require(all(event['eventSource']=='ses.amazonaws.com' for event in events.values()),'SES native audit source differs')
    require(events['create-identity']['eventCategory']=='Management','identity management category')
    sending=events['template-send'];require(sending['eventCategory']=='Data','sending data category')
    types={r['type'] for r in sending['resources']};require({'AWS::SES::EmailIdentity','AWS::SES::Template','AWS::SES::ConfigurationSet'}<=types,'SES selector resources lost')
    raw_types={r['type'] for r in events['raw-send']['resources']};require({'AWS::SES::EmailIdentity','AWS::SES::ConfigurationSet'}<=raw_types,'raw identity/default configuration selectors lost')
    serialized=json.dumps(sending);require('654321' not in serialized and 'success@simulator.amazonses.com' not in serialized,'mail content leaked to audit')
    require(sending.get('additionalEventData',{}).get('sesMessageId')==template_response['MessageId'],'message ID audit placement')
    report['observations']['cloudtrail_s3']=events
    tagging=client('resourcegroupstaggingapi');identity_arn=f'arn:aws:ses:us-east-1:{account}:identity/{sender}'
    found=tagging.get_resources(ResourceTypeFilters=['ses:identity'],TagFilters=[{'Key':'application','Values':['mail-smoke']}])['ResourceTagMappingList']
    require([r['ResourceARN'] for r in found]==[identity_arn],'SES native tags are not discoverable')
    ses.untag_resource(ResourceArn=identity_arn,TagKeys=['application'])
    history=tagging.get_resources(ResourceTypeFilters=['ses:identity'])['ResourceTagMappingList']
    require(any(r['ResourceARN']==identity_arn and r['Tags']==[] for r in history),'SES empty-tag history was not retained')
    report['observations']['ses_tag_discovery_and_empty_history']=True
    report['observations']['captured_messages']=len(messages());report['observations']['restart_preserved_mime_sha256']=digest;report['observations']['cognito_verification_reset_login']=True
except Exception as failure:
    report['failure']={'type':type(failure).__name__,'message':str(failure)}
    raise
finally:
    if controller.process and controller.process.poll() is None:
        cleanup=[]
        for kind,name in reversed(owned):
            try:
                if kind=='pool':client('cognito-idp').delete_user_pool(UserPoolId=name)
                elif kind=='linked-role':
                    # Delivery issued a real one-hour role session; expire it normally.
                    advance('61m')
                    task=client('iam').delete_service_linked_role(RoleName=name)['DeletionTaskId']
                    deletion=deletion_status(task)
                    require(deletion['Status']=='SUCCEEDED',str(deletion))
                elif kind=='trail':client('cloudtrail').delete_trail(Name=name)
                elif kind=='bucket':
                    for obj in client('s3').list_objects_v2(Bucket=name).get('Contents',[]):client('s3').delete_object(Bucket=name,Key=obj['Key'])
                    client('s3').delete_bucket(Bucket=name)
                elif kind=='template':client('sesv2').delete_email_template(TemplateName=name)
                elif kind=='identity':client('sesv2').delete_email_identity(EmailIdentity=name)
                elif kind=='configuration':client('sesv2').delete_configuration_set(ConfigurationSetName=name)
                elif kind=='user':
                    for policy in client('iam').list_user_policies(UserName=name)['PolicyNames']:client('iam').delete_user_policy(UserName=name,PolicyName=policy)
                    for key in client('iam').list_access_keys(UserName=name)['AccessKeyMetadata']:client('iam').delete_access_key(UserName=name,AccessKeyId=key['AccessKeyId'])
                    client('iam').delete_user(UserName=name)
                cleanup.append({'kind':kind,'name':name,'deleted':True})
            except Exception as e:cleanup.append({'kind':kind,'name':name,'error':str(e)})
        report['cleanup']['resources']=cleanup
    try:
        controller.stop();report['cleanup']['controller_stopped']=True
    finally:
        (state/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
