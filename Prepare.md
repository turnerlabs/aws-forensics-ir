
# Securing a new AWS Account
What to do when you create a new AWS Account to secure it

## Deploying Automations

When creating a new AWS Account, I typically do the following:

1. [Create the CloudTrail][1]
3. [Create Generic Alert topics for the account and subscribe my email and cell][3]
4. Create a stack to send certain cloudwatch events to a slack channel
5. [Configure requireMFA][4]

All of these are done via automation of course

[1]: https://github.com/jchrisfarris/aws-account-automation/blob/master/cloudformation/CloudTrailTemplate.yaml
[2]: https://github.com/jchrisfarris/aws-account-automation/blob/master/cloudformation/DeployBucketTemplate.yaml
[3]: http://www.chrisfarris.com/creating-a-set-of-generic-sns-topics/
[4]: http://www.chrisfarris.com/requiring-aws-iam-users-to-enable-mfa/
