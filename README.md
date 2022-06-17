# How to detect suspicious activity in your AWS account by using private decoy resources

This project provides the templates and source code for the blog [How to detect suspicious activity in your AWS account by using private decoy resources](https://aws.amazon.com/blogs/security/)

Follow the instructions in the blog above to deploy the code and templates without changes to the default AWS Region in the blog.

If you want to customize or change the way the resources are deployed, read on.

## Deploying the resources to a different AWS Region from the one in the blog
To deploy the template and code without changes to a different AWS Region than the one identified in the blog:

1. Clone this repository to your desktop using git.
    ```
    git clone https://github.com/aws-samples/aws-private-decoy-resources.git
    ```

2. In the AWS Region of your choice, create a new CloudFormation stack using the packaged template [rendered_template_cleaned.yaml](rendered_template_cleaned.yaml)

## Modifying the CDK and Lambda function code
This project uses [CDK in python](https://docs.aws.amazon.com/cdk/v2/guide/work-with-cdk-python.html) to generate the templates used to create resources.

To change the properties of the decoy resources created in the template or to change the Lambda function code:

1. Installing and configuring the CDK: follow the instructions in [CDK Getting Started](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html) to get started. Specifically:
- Ensure that the [pre-requisites](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html#getting_started_prerequisites) are met.
- [Install the CDK](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html#getting_started_install).
- [Bootstrap the CDK](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html#getting_started_bootstrap) with the AWS Account and Region where you want to deploy the stack.


2. Clone this repository to your desktop using git.
    ```
    git clone https://github.com/aws-samples/aws-private-decoy-resources.git
    ```

3. If you previously created a CloudFormation stack by following the instructions in the blog or by using the template [rendered_template_cleaned.yaml](rendered_template_cleaned.yaml) in this repository, you must delete the previous stack. The CDK steps below will create a new stack with new resources and will fail if resources with the same name are present in your AWS account from a previous stack.


3. Review and edit the CDK python code in [resources/resources_stack.py](resources/resources_stack.py). Make changes to the CDK code to modify the properties of the resources created.


4. Review and edit the Lambda function code in [lambda/index.py](lambda/index.py). This function is triggered by EventBridge rules and maps incoming CloudTrail API events to custom findings in Security Hub with [fields defined in ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html).

5. Synthesize the CloudFormation template for the updated code using:

```
cdk synth
```

6. Finally, you can deploy the stack to the default AWS Account and AWS Region you configured in Step 1. This command bundles the Lambda code and uploads it to the S3 bucket created for CDK artifacts.

```
cdk deploy
```
