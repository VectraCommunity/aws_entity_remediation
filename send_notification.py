import boto3

def lambda_handler(event, context):
    try:
        message = event['Records'][0]['Sns']['Message']
        subject = event['Records'][0]['Sns']['Subject']

        client = boto3.client('sns')
        snsArn = 'arn:aws:sns:Region:AccountID:TestTopic'
        message = "This is a test notification."
    
        response = client.publish(
            TopicArn = snsArn,
            Message = message ,
            Subject=subject
        )

        print(response)

    except  Exception as e:
        print(e)
        