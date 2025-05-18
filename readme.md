
# IAM User Creation Logger Lambda

This AWS Lambda function logs information when a new IAM user is created.

## What It Does

- **Triggered by IAM User Creation Events**: When a new IAM user is created (via AWS CloudTrail), this function is invoked.
- **Fetches Temporary Password**: Retrieves a temporary password from AWS Secrets Manager (`iam-users-temporary-password`).
- **Fetches Email Address**: Retrieves the user's email from AWS Systems Manager Parameter Store using the key `/iam/users/{username}/email`.
- **Logs Details**: Logs the username and email to AWS CloudWatch Logs. The password is redacted in the logs but printed to standard output.


