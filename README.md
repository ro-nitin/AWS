============================================================
 AWS IAM Role Dangerous Permissions Checker
============================================================

This Python script helps you identify dangerous permissions in an AWS IAM role by analyzing all versions of attached policies. It checks for high-risk permissions that could compromise your AWS environment and provides detailed output for remediation.

------------------------------------------------------------
 Features
------------------------------------------------------------
✔ **Dangerous Permissions Detection** - Identifies high-risk AWS permissions in IAM roles.
✔ **Policy Version Support** - Checks all versions of attached policies for dangerous permissions.
✔ **Detailed Output** - Provides the permission, policy ARN, and version ID for easy identification.
✔ **Easy to Use** - Simple command-line interface for quick analysis.

------------------------------------------------------------
 Prerequisites
------------------------------------------------------------
- Python 3.x
- AWS CLI configured with valid credentials
- Boto3 library (Install with: `pip install boto3`)

------------------------------------------------------------
 Setup
------------------------------------------------------------
1. Clone the Repository:
```bash
git clone https://github.com/ro-nitin/AWS
cd aws-iam-dangerous-permissions-checker
```
2. Install Dependencies:

pip install boto3
```
3. Configure AWS Credentials:
Ensure that AWS credentials are already added to the .aws/credentials file.
```

------------------------------------------------------------
 Usage
------------------------------------------------------------
Run the script and provide the IAM role name to analyze:
```bash
python check_dangerous_permissions.py
```

------------------------------------------------------------
 Example Output
------------------------------------------------------------
🚨 **If Dangerous Permissions Are Found:**
```
🚨 Dangerous permissions found in role 'MyRole':
- Permission: iam:CreateUser
  Policy ARN: arn:aws:iam::123456789012:policy/MyPolicy
  Version ID: v1

- Permission: s3:DeleteBucket
  Policy ARN: arn:aws:iam::123456789012:policy/MyPolicy
  Version ID: v2
```
✅ **If No Dangerous Permissions Are Found:**
```
✅ No dangerous permissions found in role 'MyRole'.
```

------------------------------------------------------------
 Dangerous Permissions List
------------------------------------------------------------
The script checks for the following high-risk AWS permissions:

- **IAM:** `iam:CreateUser`, `iam:AttachUserPolicy`, `iam:PassRole`, etc.
- **S3:** `s3:DeleteBucket`, `s3:PutBucketPolicy`, etc.
- **EC2:** `ec2:RunInstances`, `ec2:TerminateInstances`, etc.
- **Lambda:** `lambda:CreateFunction`, `lambda:UpdateFunctionCode`, etc.
- **RDS:** `rds:DeleteDBInstance`, `rds:ModifyDBInstance`, etc.
- **KMS:** `kms:Decrypt`, `kms:ScheduleKeyDeletion`, etc.

For the full list, see the script source code.

------------------------------------------------------------
 Contributing
------------------------------------------------------------
Contributions are welcome! Follow these steps to contribute:

1. Fork the repository.
2. Create a new branch:
```bash
git checkout -b feature/YourFeature
```
3. Commit your changes:
```bash
git commit -m 'Add some feature'
```
4. Push to the branch:
```bash
git push origin feature/YourFeature
```
5. Open a pull request.

------------------------------------------------------------
 License
------------------------------------------------------------
This project is licensed under the MIT License. See the LICENSE file for details.

------------------------------------------------------------
 Acknowledgments
------------------------------------------------------------
- **Boto3 Documentation**
- **AWS IAM Best Practices**

------------------------------------------------------------
 Support
------------------------------------------------------------
If you encounter any issues or have questions, please open an issue on GitHub.

------------------------------------------------------------
 Author
------------------------------------------------------------
Nitin Basera
https://github.com/ro-nitin/All/

