# AWSEntityIncidentResponse 

AWSEntityIncidentResponse is an `automated entity lockdown solution for an AWS incident` that allows `security responders` to do `forensics, eradication, and recovery during an Incident.`


This solution focuses on separating multiple targets so that each target only sees and affects itself—as a containment strategy.
AWSEntityIncidentResponse automates lockdown of an Amazon EC2 instance, an IAM User, an IAM Role, and an AWS Lambda by using an AWS Lambda function that AWS SNS triggers.
The solution supports cross-account and cross-region Incident Response. 

## Prerequisites

Before you begin, ensure you have met the following requirements:

* You have an active AWS account.
* You have IAM permissions that meet requirements to deploy solution resources through AWS Cloudformation.  
* You have AWS CLI configured (if you plan to test the solution locally)




## Installing AWSEntityIncidentResponse
To install AWSEntityIncidentResponse, follow these steps:

#### Deploy the Incident Response solution AWS resources:

To get started, download the CloudFormation template from [Amazon S3](https://aws-entity-incident-response.s3.amazonaws.com/entity_lockdown.yaml)
. Alternatively, you can launch the CloudFormation template by selecting the following [Launch Stack](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://aws-entity-incident-response.s3.amazonaws.com/entity_lockdown.yaml&stackName=AWSEntityIncidentResponse) link.


#### Deploy the Incident Response solution AWS cross-account IAM Role (only if using multiple AWS accounts):
 
Download the CloudFormation template from [Amazon S3](https://aws-entity-incident-response.s3.amazonaws.com/entity_lockdown_cross_account_role.yaml). Alternatively, you can launch the CloudFormation template by selecting the following [Launch Stack](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://aws-entity-incident-response.s3.amazonaws.com/entity_lockdown_cross_account_role.yaml&stackName=AWSEntityIncidentResponseCrossAccountRole) link




## Architecture overview

#### High level overview
![High Level](https://aws-entity-incident-response.s3.amazonaws.com/HighLeveArchitecture.PNG)

#### Detail level overview
![Detial Level](https://aws-entity-incident-response.s3.amazonaws.com/DetailLevelArchitecureV4.PNG)



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
    --sns-topic-arn=arn:aws:sns:us-east-1:888888888888:entity-lockdown-sns-topic \
    --entity_arn=arn:aws:ec2:us-east-1:888888888888:instance/i-0d205360XXXXX9a9XXX \
    --external_id=123xyz*&^
```

### Publish IAM user for incident response
```
./publish_entity_for_incident_response.py \
    --sns-topic-arn=arn:aws:sns:us-east-1:888888888888:entity-lockdown-sns-topic \
    --entity_arn=arn:aws:iam::888888888888:user/user1 \
    --external_id=123xyz*&^
```

### Publish IAM role for incident response
```
./publish_entity_for_incident_response.py \
    --sns-topic-arn=arn:aws:sns:us-east-1:888888888888:entity-lockdown-sns-topic \
    --entity_arn=arn:aws:iam::888888888888:role/service-role/role1 \
    --external_id=123xyz*&^
```

### Publish IAM role for incident response
```
./publish_entity_for_incident_response.py \
    --sns-topic-arn=arn:aws:sns:us-east-1:888888888888:entity-lockdown-sns-topic \
    --entity_arn=arn:aws:lambda:us-east-1:888888888888:function:function1 \
    --external_id=123xyz*&^
```

## Using AWSEntityIncidentResponse (From the AWS console)

To use AWSEntityIncidentResponse, follow these steps:

![AWS Console](https://aws-entity-incident-response.s3.amazonaws.com/AWSConsole.png)

## Deploy the solution

To get started follow the instructions in the Installing AWSEntityIncidentResponse section.

### Deploy the CloudFormation stack Incident Response solution AWS resources
You can leave the default values for the stack as long as there aren’t any resources provisioned already with the same name. Otherwise, the naming convention is fully customizable from this screen, and you can modify the parameters as you see fit. 

The SnsMessageExternalId Parameter does not have a default. This value is user-defined and static. Add this id to the SNS message attribute when publishing an SNS message with entity details. 

The EntityLockdownAuditSnsTopicSubscriptionEmail and EntityLockdownFailureSnsTopicSubscriptionEmail Parameters also do not have a default. These email values will be used to send Incident Response notification emails. When deploying the AWS CloudFormationstack, email address inputs will receive one-time notifications from subscribing to the newly created SNS topics. If no action is taken on the requests, then Incident Response notification emails will not reach the recipients. 

![CFNMain](https://aws-entity-incident-response.s3.amazonaws.com/cfn-main.PNG)

After you complete these steps, the following resources will be provisioned:

![CFNResources](https://aws-entity-incident-response.s3.amazonaws.com/cfn-resources.PNG)

If you are using one AWS account, then this template is all you need. However, you will need to deploy two templates if you have a multi-account setup and want a cross-account Incident Response solution. Deploying the first template in your AWS security account will host Incident Response resources. The second template will create a cross-account IAM Role in the other accounts you like the solution to cover.

Set the EntityLockdownLambdaHostAccount Parameter with the AWS account that hosts the Incident Response resources deployed by the first CloudFormation template. 
![CFNCrossAccount](https://aws-entity-incident-response.s3.amazonaws.com/cfn-cross-account.PNG)

This stack will only create one resource. And AWS IAM Role that will give the Incident Response Lambda cross-account assume role permissions. 
![CFNCrossAccountResources](https://aws-entity-incident-response.s3.amazonaws.com/cfn-resourcs-cross-account.PNG)

## Blog post
For walkthroughs and full documentation, please visit the AWSEntityIncidentResponse [blog](https://www.vectra.ai/blogpost/your-aws-has-been-breached-now-what).
