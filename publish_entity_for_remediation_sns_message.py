import boto3


def publish_entity_for_remediation(sns_topic_arn, sns_message, sns_subject, entity_arn, external_id):

    sns_client = boto3.client("sns")
    attributes={
            'Arn': {
                'DataType': 'String',
                'StringValue': entity_arn,
            },
            'ExternalId': {
                'DataType': 'String',
                'StringValue': external_id,
            }
        }
    try:
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=sns_message,
            Subject=sns_subject,
            MessageAttributes=attributes
        )['MessageId']

        print(response)

    except:
        raise