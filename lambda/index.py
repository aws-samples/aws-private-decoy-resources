import boto3
import json
import re
import traceback
import os

FINDING_SEVERITY_LABEL='HIGH'
FINDING_TYPE="Unusual Behaviors"
COMPANY_NAME="Custom"
PRODUCT_NAME="DecoyDetector"

ACCESS_DENIED_MESSAGE_REGEX = re.compile('User: (.*) is not authorized to perform: sts:AssumeRole on resource: (.*)')
IPV4_REGEX = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

MATCH_ROLE_ARN = os.environ.get('MATCH_ROLE_ARN')

USER_IDENTITY_TO_ASFF = {
    'accessKeyId': 'AccessKeyId',
    'accountId': 'AccountId',
    'principalId': 'PrincipalId',
    'type': 'PrincipalType',
    'userName': 'PrincipalName'
}

ATTRIBUTES_TO_ASFF = {
    'creationDate': 'CreationDate',
    'mfaAuthenticated': 'MfaAuthenticated'
}

SESSION_ISSUER_TO_ASFF = {
    'accountId': 'AccountId',
    'arn': 'Arn',
    'principalId': 'PrincipalId',
    'type': 'Type',
    'userName': 'UserName'
}

session = boto3.session.Session()

sts = session.client('sts')
caller_id = sts.get_caller_identity()
my_arn = caller_id['Arn']
my_account = caller_id['Account']
my_region = session.region_name
my_partition = session.get_partition_for_region(session.region_name)

sh = session.client('securityhub')

def get_resource_arn(resource_list, type):
    for r in resource_list:
        if(r['type'] == type):
            if('ARN' in r):
                return r['ARN']
            elif('ARNPrefix' in r):
                return r['ARNPrefix']
    return None

def map_keys(source, mapping):
    dest = {}
    for source_key, source_value in source.items():
        if(source_key in mapping):
            dest_key = mapping[source_key]
            dest[dest_key] = source_value
    return dest

def add_user_identity(resources, event, detail):
    user_identity = detail['userIdentity']

    # append information about the Access Key:
    access_key_resource = {
        'Id': user_identity['accessKeyId'],
        'Type': 'AwsIamAccessKey',
        'ResourceRole': 'Actor',
        'Partition': my_partition,
        'Region': event['region'],
        'Details': {}
    }

    aws_iam_access_key = map_keys(user_identity, USER_IDENTITY_TO_ASFF)

    if('sessionContext' in user_identity):
        session_context = {}
        if('attributes' in user_identity['sessionContext']):
            attr = map_keys(user_identity['sessionContext']['attributes'], ATTRIBUTES_TO_ASFF)
            if(len(attr) != 0):
                # Change type of 'MfaAuthenticated' to boolean
                if('MfaAuthenticated' in attr):
                    if(attr['MfaAuthenticated'] == 'true'):
                        attr['MfaAuthenticated'] = True
                    else:
                        attr['MfaAuthenticated'] = False

                session_context['Attributes'] = attr

        if('sessionIssuer' in user_identity['sessionContext']):
            si = map_keys(user_identity['sessionContext']['sessionIssuer'], SESSION_ISSUER_TO_ASFF)
            if(len(si) != 0):
                session_context['SessionIssuer'] = si

        if(len(session_context) != 0):
            aws_iam_access_key['SessionContext'] = session_context

    if(len(aws_iam_access_key) != 0):
        access_key_resource['Details']['AwsIamAccessKey'] = aws_iam_access_key

    resources.append(access_key_resource)

    # Now add either an AwsIamUser or AwsIamRole depending on the type of identity
    type = user_identity['type']
    if(type == 'AssumedRole'):
        role = {
            'Id': user_identity['sessionContext']['sessionIssuer']['arn'],
            'Type': 'AwsIamRole',
            'ResourceRole': 'Actor',
            'Partition': my_partition,
            'Region': event['region'],
        }
        resources.append(role)
    elif(type == 'IAMUser'):
        user = {
            'Id': user_identity['arn'],
            'Type': 'AwsIamUser',
            'ResourceRole': 'Actor',
            'Partition': my_partition,
            'Region': event['region'],
        }
        resources.append(user)


def add_s3_fields(finding, event, detail):
    add_fields = {
        "Title": f"Suspicious activity detected accessing private decoy S3 bucket {detail['requestParameters']['bucketName']}",
        "Description": f"Private decoy S3 bucket {detail['requestParameters']['bucketName']} was accessed by {detail['userIdentity']['arn']}. This S3 bucket has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
        'Resources': [
            {
                'Id': get_resource_arn(detail['resources'], 'AWS::S3::Bucket'),
                'Type': 'AwsS3Bucket',
                'ResourceRole': 'Target',
                'Partition': my_partition,
                'Region': event['region']
            },
            {
                'Id': get_resource_arn(detail['resources'], 'AWS::S3::Object'),
                'Type': 'AwsS3Object',
                'ResourceRole': 'Target',
                'Partition': my_partition,
                'Region': event['region']
            }
        ]
    }
    finding.update(add_fields)

def add_dynamodb_fields(finding, event, detail):
    table_arn = get_resource_arn(detail['resources'], 'AWS::DynamoDB::Table')
    add_fields = {
        "Title": f"Suspicious activity detected accessing private decoy DynamoDB table {table_arn}",
        "Description": f"Private decoy DynamoDB table {table_arn} was accessed by {detail['userIdentity']['arn']}. This DynamoDB table has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
        'Resources': [
            {
                'Id': table_arn,
                'Type': 'AwsDynamoDbTable',
                'ResourceRole': 'Target',
                'Partition': my_partition,
                'Region': event['region']
            }
        ]
    }
    finding.update(add_fields)


def add_sts_fields(finding, event, detail):
    if('errorCode' in detail and detail['errorCode'] == 'AccessDenied'):
        # Handle STS AccessDenied errors by parsing out IAM Role ARN from errorMessage
        error_message = detail['errorMessage']
        result = ACCESS_DENIED_MESSAGE_REGEX.fullmatch(error_message)
        if(result):
            principal_arn = result.group(1)
            target_role_arn = result.group(2)

            if(target_role_arn != MATCH_ROLE_ARN):
                raise Exception(f"STS AssumeRole AccessDenied: target role {target_role_arn} does not match {MATCH_ROLE_ARN}")
        else:
            raise Exception('STS AssumeRole AccessDenied: errorMessage did not match expected pattern')
    else:
        principal_arn = detail['userIdentity']['arn']
        target_role_arn = detail['requestParameters']['roleArn']


    add_fields = {
        "Title": f"Suspicious activity detected accessing private decoy IAM role {target_role_arn}",
        "Description": f"Private decoy IAM role {target_role_arn} was accessed by {principal_arn}. This IAM role has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
        'Resources': [
            {
                'Id': target_role_arn,
                'Type': 'AwsIamRole',
                'ResourceRole': 'Target',
                'Partition': my_partition,
                'Region': event['region']
            }
        ]
    }
    finding.update(add_fields)

def add_kms_fields(finding, event, detail):
    if(detail['requestParameters'] == None):
        # this is most likely a KMS AccessDenied error, there's not much to add here
        raise Exception(f"Missing requestParameter details for KMS event")

    enc_context = detail['requestParameters']['encryptionContext']
    if('PARAMETER_ARN' in enc_context):
        # Decryption of SSM Parameter
        add_fields = {
            "GeneratorId": 'ssm.amazonaws.com',
            "Title": f"Suspicious activity detected accessing private decoy Systems Manager parameter {enc_context['PARAMETER_ARN']}",
            "Description": f"Private decoy Systems Manager parameter {enc_context['PARAMETER_ARN']} was accessed by {detail['userIdentity']['arn']}. This Systems Manager parameter has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
            'Resources': [
                {
                    'Id': enc_context['PARAMETER_ARN'],
                    'Type': 'Other',
                    'ResourceRole': 'Target',
                    'Partition': my_partition,
                    'Region': event['region']
                }
            ]
        }

    elif('SecretARN' in enc_context):
        # Decryption of Secret
        add_fields = {
            "GeneratorId": 'secretsmanager.amazonaws.com',
            "Title": f"Suspicious activity detected accessing private decoy secret {enc_context['SecretARN']}",
            "Description": f"Private decoy secret {enc_context['SecretARN']} was accessed by {detail['userIdentity']['arn']}. This secret has been provisioned to monitor and generate security events when accessed and can be an indicator of unintended or unauthorized access to your AWS Account.",
            'Resources': [
                {
                    'Id': enc_context['SecretARN'],
                    'Type': 'AwsSecretsManagerSecret',
                    'ResourceRole': 'Target',
                    'Partition': my_partition,
                    'Region': event['region']
                }
            ]
        }
    else:
        raise Exception(f"Unexpected encryption context: {enc_context}")

    # add the KMS Key resource
    key = {
        'Id': get_resource_arn(detail['resources'], 'AWS::KMS::Key'),
        'Type': 'AwsKmsKey',
        'ResourceRole': 'Target',
        'Partition': my_partition,
        'Region': event['region']
    }
    add_fields['Resources'].append(key)

    finding.update(add_fields)


def map_finding(event):
    detail = event['detail']

    # Add common fields for all events
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": detail['eventID'],
        "ProductArn": f"arn:{my_partition}:securityhub:{my_region}:{my_account}:product/{my_account}/default",
        "GeneratorId": detail['eventSource'],
        "AwsAccountId": event['account'],
        "CreatedAt": detail['eventTime'],
        "UpdatedAt": detail['eventTime'],
        "CompanyName": COMPANY_NAME,
        "ProductName": PRODUCT_NAME,
        "FindingProviderFields": {
            "Severity": {
                "Label": FINDING_SEVERITY_LABEL
            },
            "Types": [ FINDING_TYPE ]
        },
        "Action": {
            "ActionType": "AWS_API_CALL",
            "AwsApiCallAction": {
                "Api": detail['eventName'],
                "CallerType": 'remoteIp',
                "ServiceName": detail['eventSource'],
                "RemoteIpDetails": {
                    "IpAddressV4": detail['sourceIPAddress']
                }
            }
        }
    }

    # remove IpAddressV4 if it is not an actual IPv4
    match = IPV4_REGEX.fullmatch(finding['Action']['AwsApiCallAction']['RemoteIpDetails']['IpAddressV4'])
    if(match == None):
        # Not an IPv4: this is likely an internal AWS API call: remove RemoteIpDetails
        del finding['Action']['AwsApiCallAction']['RemoteIpDetails']

    # Add additional custom product-specific fields:
    custom_fields = {}
    if('errorCode' in detail):
        custom_fields = {
            'apiResult': 'ERROR',
            'errorCode': detail['errorCode'],
            'errorMessage': detail['errorMessage']
        }
    else:
        custom_fields = {
            'apiResult': 'SUCCESS',
        }

    # Add other fields from CloudTrail Event:
    custom_fields['userAgent'] = detail['userAgent']
    custom_fields['requestID'] = detail['requestID']

    product_fields = {}
    for k, v in custom_fields.items():
        pf_key = f"{COMPANY_NAME}/{PRODUCT_NAME}/{k}"
        product_fields[pf_key] = v

    finding['ProductFields'] = product_fields
    source = event['source']

    if(source == 'aws.s3'):
        add_s3_fields(finding, event, detail)
    elif(source == 'aws.sts'):
        add_sts_fields(finding, event, detail)
    elif(source == 'aws.kms'):
        # KMS events are for SecretsManager and Systems Manager
        add_kms_fields(finding, event, detail)
    elif(source == 'aws.dynamodb'):
        add_dynamodb_fields(finding, event, detail)
    else:
        # An event source we don't recognize - this shoudn't happen so we log and ignore the event
        raise Exception(f"Unexpected event source {source}")

    add_user_identity(finding['Resources'], event, detail)
    return finding


def import_event(event):
    try:
        finding = map_finding(event)
    except Exception as e:
        print('Exception mapping event:', e, ': ignoring and not sending to Security Hub')
        traceback.print_exc()
        return

    try:
        print('Mapped ASFF finding:')
        print(json.dumps(finding))
        result = sh.batch_import_findings(Findings=[finding])
        if(result['FailedCount'] != 0):
            failed = result['FailedFindings'][0]
            print(f"Failed to import finding id {failed['Id']}: ErrorCode: {failed['ErrorCode']}, ErrorMessage: {failed['ErrorMessage']}")
        else:
            print(f"Successfully imported finding id {finding['Id']}")

    except Exception as e:
        print('Exception calling Security Hub: ', e)
        traceback.print_exc()
        return

def lambda_handler(event, context):
    print("Received EventBridge event:")
    print(json.dumps(event))
    import_event(event)
