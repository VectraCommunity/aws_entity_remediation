import boto3
import os


def lambda_handler(event, context):
    try:
        arn = event['Records'][0]['Sns']['MessageAttributes']['Arn']['Value']
        external_id = event['Records'][0]['Sns']['MessageAttributes']['ExternalId']['Value']

        if external_id != os.environ['SNSMessageExternalId']:
            raise Exception(f"Remediation SNS ExteranlId: {external_id} mismatch")
        
        _audit_remediation("Started", arn) 

        entity = _parse_message(arn)
        sts = _assume_role(entity['entity_account_id'])

        if(entity['entity_type'] == 'lambda'):
            _remediate_lambda(entity, sts)
        elif entity['entity_type'] == 'iam':
            _remediate_iam(entity, sts)
        elif entity['entity_type'] == 'ec2':
            _remediate_ec2(entity, sts)
        elif entity['entity_type'] == 'role':
            _remediate_role(entity, sts)
     
        _audit_remediation("Complete", arn)
        
    except Exception as e:
        print(e)
        message = f"{arn} - with error: {e}" 
        _audit_remediation("Failed", message)
        raise e

    return {
        "statusCode": 200
    }

def _parse_message(arn):
    entity_region = 'us-east-1'

    if arn.split(':')[2] == 'iam':
        entity_value = arn.split('/')[1]
        entity_account = arn.split(':')[4]
        entity_type = entity_type = arn.split(':')[5].split('/')[0]
    elif arn.split(':')[2] == 'lambda':
        entity_value = arn.split(':')[6]
        entity_account = arn.split(':')[4]
        entity_region = arn.split(':')[3]
        entity_type = arn.split(':')[5]
    elif arn.split(':')[2] == 'ec2':
        entity_value = arn.split('/')[1]
        entity_account = arn.split(':')[4]
        entity_region = arn.split(':')[3]
        entity_type = arn.split(':')[2]
    else:
        raise Exception(f"AWS entity {entity_type} is not supported for remediation")

    entity = {
        'entity_type':entity_type,
        'entity_value': entity_value,
        'entity_account_id': entity_account,
        'entity_region' : entity_region
    }

    return entity

def _remediate_lambda(entity, sts):
    p_arn = 'arn:aws:iam::aws:policy/AWSDenyAll'

    try:
        client_lambda = boto3.client('lambda', region_name=entity['entity_region'], aws_access_key_id = sts['aws_access_key_id'],
            aws_secret_access_key = sts['aws_secret_access_key'],
            aws_session_token = sts['aws_session_token']
        )
        response = client_lambda.get_function_configuration(FunctionName=entity['entity_value'])
        role = response['Role'].split('/')[-1]

        client_iam = boto3.client('iam', region_name=entity['entity_region'], aws_access_key_id = sts['aws_access_key_id'],
            aws_secret_access_key = sts['aws_secret_access_key'],
            aws_session_token = sts['aws_session_token']
        )
        response = client_iam.attach_role_policy(PolicyArn=p_arn, RoleName=role)

        client_lambda.put_function_concurrency( FunctionName=entity['entity_value'],ReservedConcurrentExecutions=0)

    except  Exception as e:
        print(e)
        raise e

    return {
        "statusCode": 200
    }

def _remediate_iam(entity, sts):
    p_arn = 'arn:aws:iam::aws:policy/AWSDenyAll'
    try:
        client = boto3.client('iam', aws_access_key_id = sts['aws_access_key_id'],
            aws_secret_access_key = sts['aws_secret_access_key'],
            aws_session_token = sts['aws_session_token']
        )
        
        client.attach_user_policy(PolicyArn=p_arn, UserName=entity['entity_value'])
    except Exception as e:
        print(e)
        raise e

    return {
        "statusCode": 200
    }

def _remediate_role(entity, sts):
    p_arn = 'arn:aws:iam::aws:policy/AWSDenyAll'
    
    try:
        client = boto3.client('iam', aws_access_key_id = sts['aws_access_key_id'],
            aws_secret_access_key = sts['aws_secret_access_key'],
            aws_session_token = sts['aws_session_token']
        )
        client.attach_role_policy(PolicyArn=p_arn, RoleName=entity['entity_value'])

    except Exception as e:
        print(e)
        raise e

    return {
        "statusCode": 200
    }

def _assume_role(account_id):
    sts_connection = boto3.client('sts')
    sts = sts_connection.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{os.environ['VectraRoleForRemediationLambda']}",
        RoleSessionName="cross_acct_lambda"
    )
    
    ACCESS_KEY = sts['Credentials']['AccessKeyId']
    SECRET_KEY = sts['Credentials']['SecretAccessKey']
    SESSION_TOKEN = sts['Credentials']['SessionToken']

    sts = {"aws_access_key_id":ACCESS_KEY,
    "aws_secret_access_key":SECRET_KEY,
    "aws_session_token":SESSION_TOKEN
    }
 
    return sts

def _remediate_ec2(entity, sts):
    untrack_connections_sg = 'vectra-incident-response-isolation-untrack-connections-sg'
    untrack_connections_sg_desc = 'Security Group used for incident response isolation untracking connections'
    isolation_sg = 'vectra-incident-response-isolation-sg' 
    isolation_sg_desc = 'Security Group used for incident response isolation' 

    try:
        client = boto3.client('ec2', region_name=entity['entity_region'], aws_access_key_id = sts['aws_access_key_id'],
            aws_secret_access_key = sts['aws_secret_access_key'],
            aws_session_token = sts['aws_session_token']
        )
        
        IamInstanceProfileAssociations = client.describe_iam_instance_profile_associations(Filters=[{'Name': 'instance-id','Values': [entity['entity_value']]}])['IamInstanceProfileAssociations']
        if len(IamInstanceProfileAssociations) > 0:
            for associatedIamRole in IamInstanceProfileAssociations:
                AssociationId = associatedIamRole['AssociationId']
                IamInstanceProfileArn = associatedIamRole['IamInstanceProfile']['Arn']
                print("Current IAM Instance Profile: ", IamInstanceProfileArn)
                client.disassociate_iam_instance_profile(AssociationId=AssociationId)
                print("Disassociated IAM Role for EC2 Instance: ", entity['entity_value'])

        vpcId = _remediate_ec2_identifyInstanceVpcId(entity['entity_value'], client)

        try:
            securityGroupsInVpc = client.describe_security_groups(Filters=[{'Name': 'vpc-id','Values': [vpcId]}, {'Name': 'group-name','Values': [untrack_connections_sg]}])['SecurityGroups']
            if securityGroupsInVpc:
                securityGroupId = securityGroupsInVpc[0]['GroupId']
            else:
                securityGroupId = _remediate_ec2_createSecurityGroupUntrackConnections(untrack_connections_sg, untrack_connections_sg_desc, vpcId, client)
            print(f"Modifying Instance {entity['entity_value']} with incident response isolation untracking connections security Group: {securityGroupId}")
            _remediate_ec2_modifyInstanceAttribute(entity['entity_value'], securityGroupId, client)

            securityGroupsInVpc = client.describe_security_groups(Filters=[{'Name': 'vpc-id','Values': [vpcId]}, {'Name': 'group-name','Values': [isolation_sg]}])['SecurityGroups']
            if securityGroupsInVpc:
                securityGroupId = securityGroupsInVpc[0]['GroupId']
            else:
                securityGroupId = _remediate_ec2_createSecurityGroup(isolation_sg, isolation_sg_desc, vpcId, client)
            print(f"Modifying Instance {entity['entity_value']} with incident response isolation security Group: {securityGroupId}")
            _remediate_ec2_modifyInstanceAttribute(entity['entity_value'], securityGroupId, client)

            print("Complete: Incident Response Isolation for entity type: EC2")

        except Exception as e:
            raise e
        
    except Exception as e:
        print(e)
        raise e
        
def _remediate_ec2_identifyInstanceVpcId(instanceId, client):
    instanceReservations = client.describe_instances(InstanceIds=[instanceId])['Reservations']
    for instanceReservation in instanceReservations:
        instancesDescription = instanceReservation['Instances']
        for instance in instancesDescription:
            return instance['VpcId']

def _remediate_ec2_createSecurityGroup(groupName, descriptionString, vpcId, client):
    securityGroupId = client.create_security_group(GroupName=groupName, Description=descriptionString, VpcId=vpcId)
    client.revoke_security_group_egress(GroupId = securityGroupId['GroupId'], IpPermissions= [{'IpProtocol': '-1','IpRanges': [{'CidrIp': '0.0.0.0/0'}],'Ipv6Ranges': [],'PrefixListIds': [],'UserIdGroupPairs': []}])
    client.revoke_security_group_ingress(GroupId = securityGroupId['GroupId'], IpPermissions= [{'IpProtocol': '-1','IpRanges': [{'CidrIp': '0.0.0.0/0'}],'Ipv6Ranges': [],'PrefixListIds': [],'UserIdGroupPairs': []}])
    return securityGroupId['GroupId'] 

def _remediate_ec2_createSecurityGroupUntrackConnections(groupName, descriptionString, vpcId, client):
    securityGroupId = client.create_security_group(GroupName=groupName, Description=descriptionString, VpcId=vpcId)
    client.authorize_security_group_ingress(GroupId = securityGroupId['GroupId'], IpPermissions= [{'IpProtocol': '-1','IpRanges': [{'CidrIp': '0.0.0.0/0'}],'Ipv6Ranges': [],'PrefixListIds': [],'UserIdGroupPairs': []}])
    return securityGroupId['GroupId'] 

def _remediate_ec2_modifyInstanceAttribute(instanceId,securityGroupId, client):
    client.modify_instance_attribute(
        Groups=[securityGroupId],
        InstanceId=instanceId)

def _audit_remediation(status, message):
    print(message)
    sns_client = boto3.client("sns")
    sns_topic = os.environ['VectraAuditRemediationSnsTopic']
    topic_arn = sns_topic
    message = f"Vectra entity remediation status: {status}. Details: {message}"
    subject = 'Vectra Remediation Notification'
   
    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject=subject
        )
    except Exception as e:
        print(e)
        raise e