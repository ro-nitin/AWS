import boto3

DANGEROUS_PERMISSIONS = [
    "iam:*", "iam:CreateUser", "iam:AttachUserPolicy", "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy", "iam:PassRole", "iam:PutUserPolicy", "iam:SetDefaultPolicyVersion",
    "s3:*", "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListAllMyBuckets", "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:PutBucketAcl",
    "ec2:*", "ec2:RunInstances", "ec2:TerminateInstances", "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress", "ec2:ModifyInstanceAttribute", "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
    "lambda:*", "lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction", "lambda:DeleteFunction", "lambda:AddPermission",
    "rds:*", "rds:DeleteDBInstance", "rds:DeleteDBCluster", "rds:DeleteDBSnapshot", "rds:DeleteDBClusterSnapshot", "rds:ModifyDBInstance",
    "dynamodb:*", "dynamodb:DeleteTable", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateTable",
    "kms:*", "kms:Decrypt", "kms:Encrypt", "kms:ScheduleKeyDeletion", "kms:DeleteAlias", "kms:CreateGrant",
    "cloudtrail:*", "cloudtrail:DeleteTrail", "cloudtrail:StopLogging", "cloudtrail:UpdateTrail",
    "route53:*", "route53:ChangeResourceRecordSets", "route53:DeleteHostedZone",
    "ec2:ModifyVpcEndpoint", "ec2:CreateRoute", "ec2:DeleteRoute", "ec2:ModifyVpcAttribute",
    "aws-portal:ModifyBilling", "account:ModifyAccount", "account:DisableRegion", "account:EnableRegion",
    "cloudformation:*", "cloudformation:CreateStack", "cloudformation:DeleteStack", "cloudformation:UpdateStack",
    "ssm:*", "ssm:SendCommand", "ssm:CreateDocument", "ssm:DeleteDocument",
    "ecs:*", "ecs:RunTask", "ecs:UpdateService", "ecs:DeleteService", "ecs:DeleteCluster",
    "sns:*", "sns:Publish", "sns:DeleteTopic",
    "sqs:*", "sqs:DeleteQueue", "sqs:SendMessage", "sqs:ReceiveMessage",
    "secretsmanager:*", "secretsmanager:DeleteSecret", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue",
    "cloudwatch:*", "cloudwatch:DeleteAlarms", "cloudwatch:PutMetricData",
    "glue:*", "glue:DeleteDatabase", "glue:DeleteTable", "glue:CreateJob",
    "states:*", "states:DeleteStateMachine", "states:UpdateStateMachine",
    "organizations:*", "organizations:DeleteOrganization", "organizations:LeaveOrganization"
]

def get_role_policies(iam_client, role_name):
    """
    Retrieve all policies attached to the role, including all versions.
    """
    policies = []
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    for policy in attached_policies:
        policy_arn = policy['PolicyArn']
        policy_versions = iam_client.list_policy_versions(PolicyArn=policy_arn)['Versions']
        for version in policy_versions:
            policy_document = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version['VersionId']
            )['PolicyVersion']['Document']
            policies.append({
                "PolicyArn": policy_arn,
                "VersionId": version['VersionId'],
                "Document": policy_document
            })
    return policies

def check_dangerous_permissions(policies):
    """
    Check if any dangerous permissions are present in the policies.
    """
    dangerous_permissions_found = set()
    for policy in policies:
        for statement in policy['Document'].get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if action in DANGEROUS_PERMISSIONS:
                        dangerous_permissions_found.add((action, policy['PolicyArn'], policy['VersionId']))
    return dangerous_permissions_found

def main():
    iam_client = boto3.client('iam')

    role_name = input("Enter the IAM role name to check: ")

    try:
        policies = get_role_policies(iam_client, role_name)

        dangerous_permissions = check_dangerous_permissions(policies)

        if dangerous_permissions:
            print(f"🚨 Dangerous permissions found in role '{role_name}':")
            for permission, policy_arn, version_id in dangerous_permissions:
                print(f"- Permission: {permission}")
                print(f"  Policy ARN: {policy_arn}")
                print(f"  Version ID: {version_id}")
                print("---")
        else:
            print(f"✅ No dangerous permissions found in role '{role_name}'.")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
