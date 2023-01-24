import boto3
import argparse

parser=argparse.ArgumentParser()

parser.add_argument("--sns_topic_arn", help="AWS SNS topic arn for publishing AWS entities for incident response")
parser.add_argument("--entity_arn", help="AWS entity arn for incident response")
parser.add_argument("--external_id", help="User defined enternal id")

args=parser.parse_args()

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

publish_entity_for_remediation(args.sns_topic_arn, '(message) entity for AWS incident response', '(subject) entity for AWS incident response', args.entity_arn, args.external_id)

