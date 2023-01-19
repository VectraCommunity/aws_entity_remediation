# AWSEntityIncidentResponse 

AWSEntityIncidentResponse is an `automated isolation solution for an AWS incident` that allows `security responders` to do `forensics, eradication, and recovery during an Incident.`


This solution focuses on separating multiple targets so that each target only sees and affects itself—as a containment strategy.
AWSEntityIncidentResponse automates the isolation of an Amazon EC2 instance, an IAM User, an IAM Role, and an AWS Lambda by using an AWS Lambda function that AWS SNS triggers.
The solution supports cross-account and cross-region Incident Response. 

## Prerequisites

Before you begin, ensure you have met the following requirements:

* You have an active AWS account.
* You have IAM permissions that meet requirements to deploy solution resources through AWS Cloudformation.  
* You have AWS CLI configured (if you plan to test the solution locally)




## Installing AWSEntityIncidentResponse
To install AWSEntityIncidentResponse, follow these steps:

#### Deploy the Incident Response solution AWS resources:

To get started, download the CloudFormation template from [Amazon S3](https://vectra-entity-remediation-integration.s3.amazonaws.com/remediation.yaml)
. Alternatively, you can launch the CloudFormation template by selecting the following [Launch Stack](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://vectra-entity-remediation-integration.s3.amazonaws.com/remediation.yaml&stackName=VectraAWSEntityIncidentResponse) link.


#### Deploy the Incident Response solution AWS cross-account IAM Role (only if using multiple AWS accounts):
 
Download the CloudFormation template from [Amazon S3](https://vectra-entity-remediation-integration.s3.amazonaws.com/remediation-cross-account-role.yaml). Alternatively, you can launch the CloudFormation template by selecting the following [Launch Stack](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://vectra-entity-remediation-integration.s3.amazonaws.com/remediation-cross-account-role.yaml&stackName=VectraAWSEntityIncidentResponse) link




## Architecture overview

#### High level overview
![High Level](https://vectra-entity-remediation-integration.s3.amazonaws.com/HighLeveArchitecture.PNG)

#### Detail level overview
![Detial Level](https://vectra-entity-remediation-integration.s3.amazonaws.com/DetailLevelArchitecure.PNG)



## Using AWSEntityIncidentResponse (Testing locally)

To use AWSEntityIncidentResponse, follow these steps:

### Set AWS CLI Environment variables
```
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-east-1
```

### Publish EC2 instance for incident response
```
./publish_entity_for_incident_response.py \
    --sns-topic-arn=arn:aws:sns:us-east-1:888888888888:vectra-remediation-sns-topic \
    --entity_arn=arn:aws:ec2:us-east-1:888888888888:instance/i-0d205360XXXXX9a9XXX \
    --external_id=123xyz*&^
```

### Publish IAM user for incident response
```
./publish_entity_for_incident_response.py \
    --sns-topic-arn=arn:aws:sns:us-east-1:888888888888:vectra-remediation-sns-topic \
    --entity_arn=arn:aws:iam::888888888888:user/user1 \
    --external_id=123xyz*&^
```

### Publish IAM role for incident response
```
./publish_entity_for_incident_response.py \
    --sns-topic-arn=arn:aws:sns:us-east-1:888888888888:vectra-remediation-sns-topic \
    --entity_arn=arn:aws:iam::888888888888:role/service-role/role1 \
    --external_id=123xyz*&^
```

### Publish IAM role for incident response
```
./publish_entity_for_incident_response.py \
    --sns-topic-arn=arn:aws:sns:us-east-1:888888888888:vectra-remediation-sns-topic \
    --entity_arn=arn:aws:lambda:us-east-1:888888888888:function:function1 \
    --external_id=123xyz*&^
```

## Using AWSEntityIncidentResponse (From the AWS console)

To use AWSEntityIncidentResponse, follow these steps:

![AWS Console](https://vectra-entity-remediation-integration.s3.amazonaws.com/AWSConsole.png)

## Blog post
For walkthroughs and full documentation, please visit the AWSEntityIncidentResponse [blog](https://medium.com/@alex.groyz_50998/aws-incident-response-on-the-control-plane-and-network-3ba95b0a8513).