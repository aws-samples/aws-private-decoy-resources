from aws_cdk import (
    # Duration,
    Stack,
    aws_kms as kms,
    aws_s3 as s3,
    CfnParameter as CfnParameter,
    aws_secretsmanager as secretsmanager,
    aws_iam as iam,
    aws_ssm as ssm,
    aws_dynamodb as dynamodb,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_cloudtrail as cloudtrail,
    RemovalPolicy as RemovalPolicy,
    aws_iam as iam,
    Environment as Environment,
    Aws as Aws,
    custom_resources as custom_resources,
    CfnOutput as CfnOutput,
    CustomResource as CustomResource,
    Duration as Duration
)

import json

from constructs import Construct

class ResourcesStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Decoy resources
        bucket = s3.Bucket(self, "DataBucket",
                encryption = s3.BucketEncryption.KMS_MANAGED,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                removal_policy = RemovalPolicy.DESTROY)
        bucket.node.default_child.override_logical_id('DataBucket')

        secret = secretsmanager.Secret(self, "DataSecret",
                generate_secret_string=secretsmanager.SecretStringGenerator(
                    secret_string_template=json.dumps({"username": "user"}),
                    generate_string_key="password"
                    )
                )
        secret.node.default_child.override_logical_id('DataSecret')

        ddb_table = dynamodb.Table(self, 'DataTable',
                partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
                billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                encryption=dynamodb.TableEncryption.AWS_MANAGED,
                removal_policy = RemovalPolicy.DESTROY)
        ddb_table.node.default_child.override_logical_id('DataTable')


        # Custom Lambda Resource to create SSM Paraameter of type SecureString, write an S3 Object and a DDB Item
        param_name = 'data-parameter'
        param_arn = 'arn:' + Aws.PARTITION + ':ssm:' + Aws.REGION + ':' + Aws.ACCOUNT_ID + ':parameter/' + param_name

        object_key = 'data-object'

        write_data_function_role = iam.Role(self, 'WriteDataFunctionRole',
            assumed_by = iam.ServicePrincipal("lambda.amazonaws.com")
        )
        write_data_function_role.node.default_child.override_logical_id('WriteDataFunctionRole')

        write_data_function_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))

        write_data_function_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:PutObject", "s3:DeleteObject"],
                resources=[bucket.bucket_arn + '/' + object_key]
            )
        )
        write_data_function_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ssm:PutParameter", "ssm:DeleteParameter"],
                resources=[param_arn]
            )
        )
        write_data_function_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:PutItem", "dynamodb:DeleteItem"],
                resources=[ddb_table.table_arn]
            )
        )

        write_data_function = lambda_.Function(self, 'WriteDataFunction',
                runtime = lambda_.Runtime.PYTHON_3_9,
                handler = 'index.on_event',
                role=write_data_function_role,
                timeout=Duration.minutes(5),
                code = lambda_.Code.from_inline(
"""
import json
import boto3
import uuid
import cfnresponse

ssm = boto3.client('ssm')
s3 = boto3.client('s3')
ddb = boto3.client('dynamodb')

def on_event(event, context):
  print(json.dumps(event))
  request_type = event['RequestType']
  try:
      if request_type == 'Create': return on_create(event, context)
      if request_type == 'Update': return on_update(event, context)
      if request_type == 'Delete': return on_delete(event, context)
  except Exception as e:
      print(e)
      cfnresponse.send(event, context, cfnresponse.FAILED, {})
      raise e

  raise Exception("Invalid request type: %s" % request_type)

def on_create(event, context):
  props = event["ResourceProperties"]
  print("create new resource with props %s" % props)

  ssm.put_parameter(
    Name=props['param_name'],
    Value=uuid.uuid4().hex,
    Type='SecureString',
    Overwrite=True
  )

  s3.put_object(
    Bucket=props['s3_bucket_name'],
    Key=props['s3_object_key'],
    Body=bytes(uuid.uuid4().hex, 'utf-8')
  )

  ddb.put_item(
    TableName=props['ddb_table_name'],
    Item={
        "id": {
            "S": props['ddb_item_key']
        },
        "value": {
            "S": uuid.uuid4().hex
        }
    }
  )

  cfnresponse.send(event, context, cfnresponse.SUCCESS, {
    "s3_object_key" : props['s3_object_key']
  })
  return 'Created'

def on_update(event, context):
  print("update resource - doing nothing")
  cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
  return 'Updated'

def on_delete(event, context):
  props = event["ResourceProperties"]
  print("deleting resources with props %s" % props)

  try:
      ssm.delete_parameter(
        Name=props['param_name']
      )
  except Exception as e:
      print(e)

  try:
      s3.delete_object(
        Bucket=props['s3_bucket_name'],
        Key=props['s3_object_key']
      )
  except Exception as e:
      print(e)


  try:
      ddb.delete_item(
        TableName=props['ddb_table_name'],
        Key={
            "id": {
                "S": props['ddb_item_key']
            }
        }
      )
  except Exception as e:
      print(e)

  cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
  return 'Deleted'

"""
                )
        )
        write_data_function.node.default_child.override_logical_id('WriteDataFunction')


        write_data_resource = CustomResource(self, "WriteData",
            service_token=write_data_function.function_arn,
            properties={
                "param_name" : param_name,
                "s3_bucket_name" : bucket.bucket_name,
                "s3_object_key" : object_key,
                "ddb_table_name": ddb_table.table_name,
                "ddb_item_key" : 'data-item'
            }
        )


        role = iam.Role(self, "DataRole",
            assumed_by=iam.AccountRootPrincipal()
        )
        role.node.default_child.override_logical_id('DataRole')

        # Grant decoy role permissions to read all the decoy resources
        secret.grant_read(role)
        bucket.grant_read(role)
        ddb_table.grant_read_data(role)

        role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=[param_arn]
            )
        )

        # Data Events CloudTrail

        # Python CDK does not support Advanced Event Selectors so we have to do it using Cfn resources:
        #data_events_trail = cloudtrail.Trail(self, 'DataEventsTrail',
        #    management_events = cloudtrail.ReadWriteType.NONE)

        cloudtrail_bucket = s3.Bucket(self, "DataEventsBucket",
            encryption = s3.BucketEncryption.KMS_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL)

        cloudtrail_bucket.node.default_child.override_logical_id('DataEventsBucket')

        cloudtrail_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                actions=["s3:GetBucketAcl"],
                resources=[cloudtrail_bucket.bucket_arn]
            )
        )
        cloudtrail_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                actions=["s3:PutObject"],
                resources=[cloudtrail_bucket.bucket_arn + '/AWSLogs/' + Aws.ACCOUNT_ID + '/*'],
                conditions={
                    "StringEquals" : {
                         "aws:SourceArn": 'arn:' + Aws.PARTITION + ':cloudtrail:' + Aws.REGION + ':' + Aws.ACCOUNT_ID + ':trail/data-events-trail',
                         "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            )
        )

        data_events_trail = cloudtrail.CfnTrail(self, "DataEventsTrail",
            trail_name = 'data-events-trail',
            is_logging=True,
            s3_bucket_name=cloudtrail_bucket.bucket_name,
            event_selectors=[cloudtrail.CfnTrail.EventSelectorProperty(
                data_resources=[
                    cloudtrail.CfnTrail.DataResourceProperty(
                        type="AWS::S3::Object",
                        values=[bucket.bucket_arn + '/']
                    ),
                    cloudtrail.CfnTrail.DataResourceProperty(
                        type="AWS::DynamoDB::Table",
                        values=[ddb_table.table_arn]
                    )
                ],
                include_management_events=False
            )],
            include_global_service_events=False
        )
        data_events_trail.override_logical_id('DataEventsTrail')


        # Detection pipeline
        detection_function_role = iam.Role(self, 'DataFunctionRole',
            assumed_by = iam.ServicePrincipal("lambda.amazonaws.com")
        )
        detection_function_role.node.default_child.override_logical_id('DataFunctionRole')

        detection_function_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))

        detection_function_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["securityhub:BatchImportFindings"],
                resources=[ f"arn:{Aws.PARTITION}:securityhub:{Aws.REGION}:{Aws.ACCOUNT_ID}:product/{Aws.ACCOUNT_ID}/default"]
            )
        )

        detection_function = lambda_.Function(self, 'DataFunction',
            runtime = lambda_.Runtime.PYTHON_3_9,
            handler = 'index.lambda_handler',
            role=detection_function_role,
            code = lambda_.Code.from_asset('lambda/'),
            environment={
                "MATCH_ROLE_ARN": role.role_arn
            }
        )
        detection_function.node.default_child.override_logical_id('DataFunction')

        detection_function.node.add_dependency(write_data_resource)

        ddb_rule = events.Rule(self, 'DDBRule',
            event_pattern = events.EventPattern(
                source = [
                    "aws.dynamodb"
                ],
                detail_type = ["AWS API Call via CloudTrail"],
                detail = {
                    "eventName" : [
                      "BatchExecuteStatement",
                      "BatchGetItem",
                      "BatchWriteItem",
                      "DeleteItem",
                      "ExecuteStatement",
                      "ExecuteTransaction",
                      "GetItem",
                      "PutItem",
                      "Query",
                      "Scan",
                      "TransactGetItems",
                      "TransactWriteItems",
                      "UpdateItem"
                    ],
                    "resources": {
                      "ARN": [ddb_table.table_arn],
                      "type": ["AWS::DynamoDB::Table"]
                    }
                }
            )
        )
        ddb_rule.node.default_child.override_logical_id('DDBRule')
        ddb_rule.add_target(events_targets.LambdaFunction(detection_function))

        s3_rule = events.Rule(self, 'S3Rule',
            event_pattern = events.EventPattern(
                source = [
                    "aws.s3"
                ],
                detail_type = ["AWS API Call via CloudTrail"],
                detail = {
                    "eventName" : [
                        "HeadObject",

                        "GetObject",
                        "GetObjectAcl",
                        "GetObjectAttributes",
                        "GetObjectLegalHold",
                        "GetObjectLockConfiguration",
                        "GetObjectRetention",
                        "GetObjectTagging",
                        "GetObjectTorrent",

                        "PutObject",
                        "PutObjectAcl",
                        "PutObjectLegalHold",
                        "PutObjectLockConfiguration",
                        "PutObjectRetention",
                        "PutObjectTagging",
                        "SelectObjectContent",

                        "DeleteObject",
                        "DeleteObjects",
                        "DeleteObjectTagging"
                    ],
                    "resources": {
                      "ARN": [bucket.bucket_arn],
                      "type": ["AWS::S3::Bucket"]
                    }
                }
            )
        )
        s3_rule.node.default_child.override_logical_id('S3Rule')
        s3_rule.add_target(events_targets.LambdaFunction(detection_function))

        # this rule matches successful STS AssumeRole events that have the Role ARN in the resources field
        sts_rule = events.Rule(self, 'STSRule',
            event_pattern = events.EventPattern(
                source = [
                    "aws.sts"
                ],
                detail_type = ["AWS API Call via CloudTrail"],
                detail = {
                    "eventName" : [
                        "AssumeRole"
                    ],
                    "resources": {
                      "ARN": [role.role_arn],
                      "type": ["AWS::IAM::Role"]
                    }
                }
            )
        )
        sts_rule.node.default_child.override_logical_id('STSRule')
        sts_rule.add_target(events_targets.LambdaFunction(detection_function))

        # this rule matches STS AssumeRole AccessDenied events for ALL roles:
        # The detection function filters amd sends Security Hub findings for the decoy role only
        sts_access_denied_rule = events.Rule(self, 'STSAccessDeniedRule',
            event_pattern = events.EventPattern(
                source = [
                    "aws.sts"
                ],
                detail_type = ["AWS API Call via CloudTrail"],
                detail = {
                    "eventName" : [
                        "AssumeRole"
                    ],
                    "errorCode" : [
                        "AccessDenied"
                    ]
                }
            )
        )
        sts_access_denied_rule.node.default_child.override_logical_id('STSAccessDeniedRule')
        sts_access_denied_rule.add_target(events_targets.LambdaFunction(detection_function))

        kms_secret_rule = events.Rule(self, 'KMSSecretRule',
            event_pattern = events.EventPattern(
                source = [
                    "aws.kms"
                ],
                detail_type = ["AWS API Call via CloudTrail"],
                detail = {
                    "eventName" : [
                        "Decrypt",
                        "Encrypt",
                        "GenerateDataKey"
                    ],
                    "requestParameters" : {
                        "encryptionContext": {
                            "SecretARN": [secret.secret_arn]
                        }
                    }
                }
            )
        )
        kms_secret_rule.node.default_child.override_logical_id('KMSSecretRule')
        kms_secret_rule.add_target(events_targets.LambdaFunction(detection_function))

        kms_param_rule = events.Rule(self, 'KMSParamRule',
            event_pattern = events.EventPattern(
                source = [
                    "aws.kms"
                ],
                detail_type = ["AWS API Call via CloudTrail"],
                detail = {
                    "eventName" : [
                        "Decrypt"
                    ],
                    "requestParameters" : {
                        "encryptionContext": {
                            "PARAMETER_ARN": [param_arn]
                        }
                    }
                }
            )
        )
        kms_param_rule.node.default_child.override_logical_id('KMSParamRule')
        kms_param_rule.add_target(events_targets.LambdaFunction(detection_function))

        CfnOutput(self, "SSMParameterName", value=param_name)
        CfnOutput(self, "S3ObjectKey", value=object_key)
        CfnOutput(self, "S3BucketName", value=bucket.bucket_name)
        CfnOutput(self, "S3ObjectUri", value= 's3://' + bucket.bucket_name + '/' + object_key)
        CfnOutput(self, "SecretArn", value=secret.secret_arn)
        CfnOutput(self, "IAMRoleArn", value=role.role_arn)
        CfnOutput(self, "DynamoDBTableName", value=ddb_table.table_name)
