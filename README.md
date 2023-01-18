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

Deploy the Incident Response solution AWS resources:

To get started, download the CloudFormation template from [Amazon S3](https://vectra-entity-remediation-integration.s3.amazonaws.com/remediation.yaml)
. Alternatively, you can launch the CloudFormation template by selecting the following [Launch Stack](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://vectra-entity-remediation-integration.s3.amazonaws.com/remediation.yaml&stackName=VectraAWSEntityIncidentResponse) link.



Deploy the Incident Response solution AWS cross-account IAM Role (only if using multiple AWS accounts):
 
Download the CloudFormation template from [Amazon S3](https://vectra-entity-remediation-integration.s3.amazonaws.com/remediation-cross-account-role.yaml). Alternatively, you can launch the CloudFormation template by selecting the following [Launch Stack](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://vectra-entity-remediation-integration.s3.amazonaws.com/remediation-cross-account-role.yaml) link

## High Level Architecture overview

[High Level Architecture](HighLeveArchitecture.PNG)


## Using <project_name>

To use <project_name>, follow these steps:

```
<usage_example>
```

Add run commands and examples you think users will find useful. Provide an options reference for bonus points!

## Contributing to <project_name>
<!--- If your README is long or you have some specific process or steps you want contributors to follow, consider creating a separate CONTRIBUTING.md file--->
To contribute to <project_name>, follow these steps:

1. Fork this repository.
2. Create a branch: `git checkout -b <branch_name>`.
3. Make your changes and commit them: `git commit -m '<commit_message>'`
4. Push to the original branch: `git push origin <project_name>/<location>`
5. Create the pull request.

Alternatively see the GitHub documentation on [creating a pull request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request).

## Contributors

Thanks to the following people who have contributed to this project:

* [@scottydocs](https://github.com/scottydocs) 📖
* [@cainwatson](https://github.com/cainwatson) 🐛
* [@calchuchesta](https://github.com/calchuchesta) 🐛

You might want to consider using something like the [All Contributors](https://github.com/all-contributors/all-contributors) specification and its [emoji key](https://allcontributors.org/docs/en/emoji-key).

## Contact

If you want to contact me you can reach me at <your_email@address.com>.

## License
<!--- If you're not sure which open license to use see https://choosealicense.com/--->

This project uses the following license: [<license_name>](<link>).