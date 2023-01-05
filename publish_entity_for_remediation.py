import boto3

sns_client = boto3.client("sns")

arn = 'arn:aws:ec2:us-east-1:123456789012:instance/i-012abcd34efghi56'
topic_arn = 'arn:aws:sns:us-east-1:602592549188:RemediateEntityTopic'
message = 'This is a test message on topic.'
subject = 'remediate entity'
attributes={
        'arn': {
            'DataType': 'String',
            'StringValue': arn,
        }
    }
try:
    response = sns_client.publish(
        TopicArn=topic_arn,
        Message=message,
        Subject=subject,
        MessageAttributes=attributes
    )['MessageId']

except:
    raise