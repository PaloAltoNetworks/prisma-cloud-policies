# Changelog

## PCS-24.7.3 - 2024-7-31

### Added

#### 13 new config policies

- AWS Elastic Load Balancer v2 (ELBv2) with deletion protection disabled
- AWS MSK clusters not configured with enhanced monitoring
- AWS Network ACLs allow ingress traffic on Admin ports 22/3389
- AWS Route53 public Hosted Zone query logging is not enabled
- Azure Key Vault Role Based Access control is disabled
- Azure Microsoft Defender for IoT Hub not enabled
- Azure Network Security Group having Inbound rule overly permissive to HTTP(S) traffic
- Azure subscription permission for Microsoft Entra tenant is set to ‘Allow everyone’
- OCI API Gateway is not configured with Network Security Groups
- OCI Data Catalog configured with overly permissive network access
- OCI Function Application is not configured with Network Security Groups
- OCI Load balancer backend set not configured with SSL certificate
- OCI Load balancer not configured with Network Security Groups

### Changed

#### 9 policies updated for the IAM Security module

- AWS Role With Administrative Permissions Can Be Assumed By All Users
- AWS Users and Machine Identities with Excessive Policies
- Cloud service account with excessive admin privileges
- GCP Cloud Run Job Public Execution via Default Compute SA Modification
- GCP Cloud Run with administrative permissions
- GCP Lateral Access Expansion by Making Cloud Run Publicly Executable
- Roles with high privileges can be assumed by a service in an external account
- Third-party service account can assume a service account with high privileges
- User account with excessive admin privileges

#### 2 compliance standards updated

- CIS v2.0.0 (GCP) Level 1
- CIS v3.0.0 (GCP) Level 2


## PCS-24.7.2 - 2024-7-18

### Added

#### 16 new config policies

- AWS CloudWatch log groups retention set to less than 365 days
- AWS CodeBuild project not configured with logging configuration
- AWS DAX cluster not configured with encryption at rest
- AWS ECS task definition is not configured with read-only access to container root filesystems
- AWS Elastic Beanstalk environment managed platform updates are not enabled
- AWS ElastiCache cluster not using supported engine version
- AWS ElastiCache Redis cluster automatic version upgrade disabled
- Azure Active Directory MFA is not enabled for user
- Azure Machine learning workspace configured with high business impact data have unrestricted network access
- Google Workspace Super Admin not enrolled with 2-step verification
- Google Workspace User not enrolled with 2-step verification
- OCI Autonomous Database not registered in Data Safe
- OCI Load Balancer not configured with backend set
- OCI Load Balancer not configured with inbound rules or listeners
- OCI Network Load Balancer not configured with backend set
- OCI Network Load Balancer not configured with inbound rules or listeners

#### 4 new compliance standards

- Australian Cyber Security Centre (ACSC) Essential Eight - Level 1
- Australian Cyber Security Centre (ACSC) Essential Eight - Level 2
- Australian Cyber Security Centre (ACSC) Essential Eight - Level 3
- Digital Operational Resilience Act (DORA)

### Changed

#### 2 compliance standards updated

- CIS v3.0.0 (GCP) Level 1
- SOC 2

### Removed

#### 1 policy deleted

- Azure AD MFA is not enabled for the user


## PCS-24.7.1 - 2024-7-08

### Added

#### 14 new config policies

- AWS CodeBuild project environment variables contain plaintext AWS credentials
- AWS DMS replication task for the source database have logging not set to the minimum severity level
- AWS DMS replication task for the target database have logging not set to the minimum severity level
- AWS ElastiCache Redis cluster is not configured with automatic backup
- AWS Log metric filter and alarm does  not exist for management console sign-in without MFA
- AWS Log metric filter and alarm does not exist for AWS Security group changes
- Azure Logic app configured with public network access
- Azure Logic app does not redirect HTTP requests to HTTPS
- Azure Logic App does not utilize HTTP 2.0 version
- Azure Logic app is not configured with managed identity
- Azure Logic app using insecure TLS version
- OCI Database system is not configured with Network Security Groups
- OCI Load balancer listener allows connection requests over HTTP
- OCI Load balancer listener is not configured with SSL certificate

### Changed

#### 7 policies updated for the IAM Security module

- AWS Lateral Movement to Data Services Through Redshift Cluster Creation
- Azure Lateral Movement Through SSH Key Replacement and Managed Identity Exploitation on VM
- Azure Lateral Movement via VM Command Execution Leveraging Managed Identity
- GCP Cloud Run Job Public Execution via Default Compute SA Modification
- GCP Lateral Access Expansion by Making Cloud Run Publicly Executable
- GCP Project-Wide Lateral Movement via SSH Key Modification for VMs
- Third-party Service Account With Lateral Movement Through CloudFormation Stack Creation

#### 2 compliance standards updated

- CIS v3.0.0 (GCP) Level 1
- CIS v3.0.0 (GCP) Level 2


## PCS-24.6.2 - 2024-6-20

### Added

#### 15 new config policies

- AWS ECR private repository tag mutable
- AWS IAM group not in use
- AWS Opensearch domain audit logging disabled
- AWS Opensearch domain Error logging disabled
- AWS S3 bucket is utilized for AWS Sagemaker training job data
- AWS S3 bucket used for storing AWS Sagemaker training job output
- Azure Application Gateway WAF policy is not enabled in prevention mode
- Azure Key vault used for machine learning workspace secrets storage is not enabled with audit logging
- Azure Storage Account storing Cognitive service diagnostic logs is publicly accessible
- GCP Storage Bucket storing GCP Vertex AI pipeline output data
- GCP Storage Bucket storing GCP Vertex AI training pipeline output model
- GCP Storage Bucket storing Vertex AI model
- OCI Oracle Analytics Cloud (OAC) access is not restricted to allowed sources or deployed within a Virtual Cloud Network
- OCI Oracle Autonomous Database (ADB) access is not restricted to allowed sources or deployed within a Virtual Cloud Network
- OCI VCN subnet flow logging is disabled

### Changed

#### 6 config policies updated

- Azure Function App client certificate is disabled
- Azure Function app configured with public network access
- Azure Function App doesn’t have a Managed Service Identity
- Azure Function App doesn’t redirect HTTP to HTTPS
- Azure Function App doesn’t use HTTP 2.0
- Azure Function App doesn’t use latest TLS version

#### 3 compliance standards updated

- AWS CIS 2.0
- GCP CIS 2.0
- ISO/IEC 27001:2022


## PCS-24.6.1 - 2024-6-09

### Added

#### 23 new config policies

- AWS AppSync GraphQL API is authenticated with API key
- AWS Aurora MySQL DB cluster does not publish audit logs to CloudWatch Logs
- AWS EC2 Client VPN endpoints client connection logging disabled
- AWS ECS task definition logging configuration disabled
- AWS EventBridge event bus with no resource-based policy attached
- AWS Network Firewall is not configured with logging configuration
- AWS Secrets Manager secret not used for more than 90 days
- AWS Security Hub is not enabled
- AWS Step Function state machines logging disabled
- AWS WAF Rule Group CloudWatch metrics disabled
- Azure Activity log alert for Create or update public IP address rule does not exist
- Azure Activity log alert for Delete public IP address rule does not exist
- Azure Application Insights configured with overly permissive network access
- Azure Application Insights not configured with Azure Active Directory (Azure AD) authentication
- Azure Log Analytics workspace configured with overly permissive network access
- Azure storage account infrastructure encryption is disabled
- GCP Cloud Run service revision is using default service account with editor role
- GCP Vertex AI Workbench user-managed notebook auto-upgrade is disabled
- GCP Vertex AI Workbench user-managed notebook has Integrity monitoring disabled
- GCP Vertex AI Workbench user-managed notebook has vTPM disabled
- GCP Vertex AI Workbench user-managed notebook’s JupyterLab interface access mode is set to single user
- OCI boot volume is not encrypted with Customer Managed Key (CMK)
- OCI Cloud Guard is not enabled in the root compartment of the tenancy

#### 35 new policies for the IAM Security module

- AWS Compute Instance (EC2/Lambda) Assigned CloudFormation Creation Permissions Which Could Lead to Privilege Escalation
- AWS Compute Instance (EC2/Lambda) Assigned Glue DevEndpoint Creation Permissions Which Could Lead to Privilege Escalation
- AWS Compute Instance (EC2/Lambda) Assigned IAM Policy Management Permissions Which Could Lead to Privilege Escalation
- AWS Compute Instance (EC2/Lambda) Assigned Lambda Creation Permissions Which Could Lead to Privilege Escalation
- AWS Compute Instance (EC2/Lambda) Assigned Permissions to Run EC2 Instances Which Could Lead to Privilege Escalation
- AWS Role With Administrative Permissions Can Be Assumed By All Users
- Azure Compute Resource Assigned Managed Identity Assignment Permissions Which Could Lead to Privilege Escalation
- Azure Compute Resource Assigned Role & Role Assignment Related Permissions Which Could Lead to Privilege Escalation
- GCP App Engine Web Service Assigned Cloud Function Creation Permissions Which Could Lead to Privilege Escalation
- GCP App Engine Web Service Assigned Cloud Function IAM Policy Edit Permissions Which Could Lead to Privilege Escalation
- GCP App Engine Web Service Assigned Cloud Run Creation Which Could Lead to Privilege Escalation
- GCP App Engine Web Service Assigned Cloud Run IAM Policy Edit Permissions Which Could Lead to Privilege Escalation
- GCP App Engine Web Service Assigned Cloud Run Jobs IAM Policy Edit Permissions Which Could Lead to Privilege Escalation
- GCP App Engine Web Service Assigned IAM Role Update Permissions Which Could Lead to Privilege Escalation
- GCP App Engine Web Service Assigned Permissions to Edit IAM Policy for Service Accounts Which Could Lead to Privilege Escalation
- GCP App Engine Web Service Assigned Permissions to Retrieve Service Account Tokens Which Could Lead to Privilege Escalation
- GCP App Engine Web Service Assigned Resource Manager Permissions Which Could Lead to Privilege Escalation
- GCP Cloud Run Instance Assigned Cloud Function Creation Permissions Which Could Lead to Privilege Escalation
- GCP Cloud Run Instance Assigned Cloud Function IAM Policy Edit Permissions Which Could Lead to Privilege Escalation
- GCP Cloud Run Instance Assigned Cloud Run Creation Which Could Lead to Privilege Escalation
- GCP Cloud Run Instance Assigned Cloud Run IAM Policy Edit Permissions Which Could Lead to Privilege Escalation
- GCP Cloud Run Instance Assigned Cloud Run Jobs IAM Policy Edit Permissions Which Could Lead to Privilege Escalation
- GCP Cloud Run Instance Assigned IAM Role Update Permissions Which Could Lead to Privilege Escalation
- GCP Cloud Run Instance Assigned Permissions to Edit IAM Policy for Service Accounts Which Could Lead to Privilege Escalation
- GCP Cloud Run Instance Assigned Permissions to Retrieve Service Account Tokens Which Could Lead to Privilege Escalation
- GCP Cloud Run Instance Assigned Resource Manager Permissions Which Could Lead to Privilege Escalation
- GCP Compute Instance (VM/Cloud Function) Assigned Cloud Function Creation Permissions Which Could Lead to Privilege Escalation
- GCP Compute Instance (VM/Cloud Function) Assigned Cloud Function IAM Policy Edit Permissions Which Could Lead to Privilege Escalation
- GCP Compute Instance (VM/Cloud Function) Assigned Cloud Run Creation Permissions Which Could Lead to Privilege Escalation
- GCP Compute Instance (VM/Cloud Function) Assigned Cloud Run IAM Policy Edit Permissions Which Could Lead to Privilege Escalation
- GCP Compute Instance (VM/Cloud Function) Assigned Cloud Run Jobs IAM Policy Edit Permissions Which Could Lead to Privilege Escalation
- GCP Compute Instance (VM/Cloud Function) Assigned IAM Role Update Permissions Which Could Lead to Privilege Escalation
- GCP Compute Instance (VM/Cloud Function) Assigned Permissions to Edit IAM Policy for Service Accounts Which Could Lead to Privilege Escalation
- GCP Compute Instance (VM/Cloud Function) Assigned Permissions to Retrieve Service Account Tokens Which Could Lead to Privilege Escalation
- GCP Compute Instance (VM/Cloud Function) Assigned Resource Manager Permissions Which Could Lead to Privilege Escalation

#### 4 new compliance standards

- CIS AWS 3.0
- CIS Azure 2.1
- CIS GKE 1.5
- CIS OCI 2.0

### Changed

#### 1 config policy updated

- AWS AppSync has field-level logging disabled

#### 1 policy updated for the IAM Security module

- AWS IAM Groups and Roles with IAM Metadata Write permissions are unused for 90 days

#### 5 legacy versions of compliance standards deprecated

- HITRUST CSF v9.3
- HITRUST v.9.4.2
- MITRE ATT&CK v10.0
- MITRE ATT&CK v6.3
- MITRE ATT&CK v8.2


## PCS-24.5.2 - 2024-5-23

### Added

#### 9 new config policies

- AWS Application Load Balancer (ALB) is not configured to drop HTTP headers
- AWS DocumentDB cluster does not publish audit logs to CloudWatch Logs
- AWS Neptune DB cluster does not publish audit logs to CloudWatch Logs
- AWS Neptune DB clusters have backup retention period less than 7 days
- AWS Network Firewall delete protection is disabled
- AWS OpenSearch domain does not have the latest service software version
- Azure App Service Environment configured with weak TLS cipher suites
- Azure App service HTTP logging is disabled
- Azure Storage account with cross tenant replication enabled

#### 43 new policies for the IAM Security module

- AWS Administrators with IAM permissions are unused for 90 days
- AWS Groups and IAM Roles with Administrative Permissions
- AWS IAM Groups and Roles with Excessive Policies
- AWS IAM Groups and Roles with IAM Data Read permissions are unused for 90 days
- AWS IAM Groups and Roles with IAM Data Write permissions are unused for 90 days
- AWS IAM Groups and Roles with IAM Metadata Read permissions are unused for 90 days
- AWS IAM Groups and Roles with IAM Metadata Write permissions are unused for 90 days
- AWS Users and Machine Identities with Administrative Permissions
- AWS Users and Machine Identities with Excessive Policies
- AWS Users and Machine Identities with IAM Data Read permissions are unused for 90 days
- AWS Users and Machine Identities with IAM Data Write permissions are unused for 90 days
- AWS Users and Machine Identities with IAM Metadata Read permissions are unused for 90 days
- AWS Users and Machine Identities with IAM Metadata Write permissions are unused for 90 days
- Azure AD Groups, Service Principals and Managed Identities with Administrative Permissions
- Azure AD Groups, Service Principals and Managed Identities with Excessive Policies
- Azure AD Groups, Service Principals and Managed Identities with IAM Data Read permissions are unused for 90 days
- Azure AD Groups, Service Principals and Managed Identities with IAM Data Write permissions are unused for 90 days
- Azure AD Groups, Service Principals and Managed Identities with IAM Metadata Read permissions are unused for 90 days
- Azure AD Groups, Service Principals and Managed Identities with IAM Metadata Write permissions are unused for 90 days
- Azure Administrators with IAM permissions are unused for 90 days
- Azure Users and Machine Identities with Administrative Permissions
- Azure Users and Machine Identities with Excessive Policies
- Azure Users and Machine Identities with IAM Data Read permissions are unused for 90 days
- Azure Users and Machine Identities with IAM Data Write permissions are unused for 90 days
- Azure Users and Machine Identities with IAM Metadata Read permissions are unused for 90 days
- Azure Users and Machine Identities with IAM Metadata Write permissions are unused for 90 days
- GCP Administrators with IAM permissions are unused for 90 days
- GCP Groups and Service Accounts with Administrative Permissions
- GCP Groups and Service Accounts with Excessive Policies
- GCP Groups and Service Accounts with IAM Data Read permissions are unused for 90 days
- GCP Groups and Service Accounts with IAM Data Write permissions are unused for 90 days
- GCP Groups and Service Accounts with IAM Metadata Read permissions are unused for 90 days
- GCP Groups and Service Accounts with IAM Metadata Write permissions are unused for 90 days
- GCP Users and Machine Identities with Administrative Permissions
- GCP Users and Machine Identities with Excessive Policies
- GCP Users and Machine Identities with IAM Data Read permissions are unused for 90 days
- GCP Users and Machine Identities with IAM Data Write permissions are unused for 90 days
- GCP Users and Machine Identities with IAM Metadata Read permissions are unused for 90 days
- GCP Users and Machine Identities with IAM Metadata Write permissions are unused for 90 days
- Third-party service account can assume a service account with high privileges
- Third-party service account with a Lateral Movement Through Lambda Edit
- Third-party service account with a Lateral Movement to Data Services Through Redshift Cluster Creation
- Third-party Service Account With Lateral Movement Through CloudFormation Stack Creation

#### 1 new compliance standard

- NIST CSF v2.0

### Changed

#### 3 config policies updated

- Azure App Service Web app authentication is off
- Azure Storage account encryption key configured by access policy with privileged operations
- Azure Virtual Network subnet is not configured with a Network Security Group

#### 10 policies updated for the IAM Security module

- GCP service accounts with 'Editor' role on folder level
- GCP service accounts with 'Editor' role on org level
- GCP service accounts with 'Owner' role on folder level
- GCP service accounts with 'Owner' role on org level
- GCP service accounts with permissions to deploy new resources
- GCP users with 'Editor' role on folder level
- GCP users with 'Editor' role on org level
- GCP users with 'Owner' role on org level
- GCP users with permissions to deploy new resources
- GCP users with Service Account Token Creator role

#### 1 compliance standard updated

- HIPAA


## PCS-24.5.1 - 2024-5-09

### Added

#### 12 new config policies

- AWS AppSync has field-level logging disabled
- AWS Certificate Manager (ACM) RSA certificate key length less than 2048
- AWS DMS replication instance automatic version upgrade disabled
- AWS DocumentDB clusters have backup retention period less than 7 days
- AWS DynamoDB table Auto Scaling not enabled
- AWS DynamoDB table deletion protection is disabled
- AWS Elastic Beanstalk environment logging not configured
- AWS Macie is not enabled
- AWS Network ACL is not in use
- GCP Cloud Asset Inventory is disabled
- GCP External Load Balancer logging is disabled
- GCP VM instance Confidential VM service disabled

#### 2 new compliance standards

- CIS v3.0.0 (GCP) Level 1
- CIS v3.0.0 (GCP) Level 2

### Changed

#### 2 config policies updated

- AWS Application Load Balancer (ALB) is not using the latest predefined security policy
- Azure Microsoft Defender for Cloud set to Off for DNS


## PCS-24.4.2 - 2024-4-25

### Added

#### 5 new policies

- AWS Cognito identity pool allows unauthenticated guest access
- AWS DynamoDB table point-in-time recovery (PITR) disabled
- AWS Glue Data Catalog not encrypted by Customer Managed Key (CMK)
- AWS GuardDuty detector is not enabled
- GCP Service account is publicly accessible

#### 11 new policies for the IAM Security module

- AWS Lateral Movement to Data Services Through Redshift Cluster Creation
- Azure Lateral Movement Through SSH Key Replacement and Managed Identity Exploitation on VM
- Azure Lateral Movement via VM Command Execution Leveraging Managed Identity
- Cloud service account with excessive admin privileges
- GCP Cloud Run Job Public Execution via Default Compute SA Modification
- GCP Cloud Run with administrative permissions
- GCP Cloud Run with basic role
- GCP Lateral Access Expansion by Making Cloud Run Publicly Executable
- GCP Project-Wide Lateral Movement via SSH Key Modification for VMs
- Roles with high privileges can be assumed by a service in an external account
- User account with excessive admin privileges


#### 1 new compliance standard

- CRI Profile v2.0

### Changed

#### 5 policies updated

- Alibaba Cloud RAM user has both console access and access keys
- AWS EBS volume region with encryption is disabled
- AWS EC2 Instance Scheduled Events
- AWS EMR cluster is not enabled with data encryption in transit
- Azure Function app configured with public network access


## PCS-24.4.1 - 2024-4-11

### Added

#### 10 new policies

- AWS Athena Workgroup data encryption at rest not configured
- AWS DMS replication instance is publicly accessible
- AWS EC2 Auto Scaling Launch Configuration is not using encrypted EBS volumes
- AWS Glue Job not encrypted by Customer Managed Key (CMK)
- AWS RDS cluster encryption in transit is not configured
- AWS root account activity detected in last 14 days
- AWS SageMaker endpoint data encryption at rest not configured
- AWS Secrets Manager secret not encrypted by Customer Managed Key (CMK)
- Azure Storage Sync Service configured with overly permissive network acce
- GCP Storage Bucket encryption not configured with Customer-Managed Encryption Key (CMEK)

#### 2 new policies for the IAM Security module

- Publicly Writable Lambda
- Publicly Readable Lambda

### Changed

#### 5 policies updated

- AWS EC2 instance that is internet reachable with unrestricted access (0.0.0.0/0) on Admin ports 22/3389
- AWS MFA is not enabled on Root account
- AWS S3 bucket encrypted using Customer Managed Key (CMK) with overly permissive policy
- Azure Virtual Machine that is internet reachable with unrestricted access (0.0.0.0/0) on Admin ports 22/3389
- GCP VM instance that is internet reachable with unrestricted access (0.0.0.0/0) on Admin ports 22/3389

#### 2 policies updated for the IAM Security module

- AWS cross-account resource access through IAM policies
- Publicly Executable Lambda

### Removed

#### 1 policy deleted from the IAM Security module

- Azure Managed Identity with permissions to other subscriptions


## PCS-24.3.2 - 2024-3-28

### Added

#### 22 new policies

- AWS CloudTrail S3 bucket encrypted with Customer Managed Key (CMK) that is scheduled for deletion
- AWS Cognito service role does not have identity pool verification
- AWS Cognito service role with wide privileges does not validate authentication
- AWS Default VPC is being used
- AWS EKS cluster does not have secrets encryption enabled
- AWS Elastic Load Balancer v2 (ELBv2) with cross-zone load balancing disabled
- AWS MQ Broker is not encrypted by Customer Managed Key (CMK)
- AWS MSK cluster encryption in transit is not enabled
- AWS RDS database instance not configured with encryption in transit
- AWS RDS Postgres Cluster does not have query logging enabled
- AWS Redshift cluster instance with public access setting enabled
- AWS Redshift cluster with commonly used master username and public access setting enabled
- AWS SNS Topic not encrypted by Customer Managed Key (CMK)
- GCP Cloud Run service is using default service account with editor role
- GCP Composer environment web server network access control allows access from all IP addresses
- GCP Dataproc Cluster not configured with Customer-Managed Encryption Key (CMEK)
- GCP GKE cluster node boot disk not encrypted with CMEK
- GCP PostgreSQL instance database flag cloudsql.enable_pgaudit is not set to on
- GCP PostgreSQL instance database flag log_min_error_statement is not set
- GCP SQL Instance with public IP address does not have authorized network configured
- GCP Vertex AI Workbench user-managed notebook is using default service account with the editor role
- GCP VM instance serial port output logging is enabled

#### 3 new compliance standards

- HITRUST CSF v.11.2.0
- NIST 800-53 Rev 5
- Telecommunications Security Act - TSA

### Changed

#### 3 policies updated

- AWS SQS queue access policy is overly permissive
- Azure Microsoft Defender for Cloud set to Off for DNS
- GCP Storage buckets are publicly accessible to all users


## PCS-24.2.2 - 2024-3-05

### Added

#### 9 new policies

- AWS account security contact information is not set
- AWS Systems Manager EC2 instance having NON_COMPLIANT patch compliance status
- Azure Batch Account configured with overly permissive network access
- Azure Cognitive Services account configured with local authentication
- Azure Machine learning workspace is not configured with private endpoint
- Azure Microsoft Defender for Cloud set to Off for Cosmos DB
- Azure Microsoft Defender for Cloud set to Off for Databases
- Azure Microsoft Defender for Cloud set to Off for Open-Source Relational Databases
- Azure Storage Account storing Machine Learning workspace high business impact data is publicly accessible

#### 1 new compliance standard

- Risk Management in Technology (RMiT)

### Changed

#### 1 policy updated

- GCP Cloud Armor policy not configured with cve-canary rule

#### 2 compliance standards updated

- CIS v2.0.0 (Azure) Level 2
- CIS v1.5.0 (Azure) Level 2

## PCS-24.2.1 - 2024-2-20

### Added

#### 3 new policies

- AWS IAM AWSCloudShellFullAccess policy is attached to IAM roles, users, or IAM groups
- AWS Log metric filter and alarm does not exist for AWS Organization changes
- AWS Log metric filter and alarm does not exist for usage of root account


## PCS-24.1.2 - 2024-1-31

### Added

#### 3 new policies

- Azure Cognitive Services account configured with public network access
- Azure Cognitive Services account is not configured with managed identity
- Azure Cognitive Services account not configured with private endpoint

#### 2 new compliance standards

- Framework for Adoption of Cloud Services by SEBI Regulated Entities (REs)
- RBI Baseline Cyber Security and Resilience Requirements

### Changed

#### 1 policy updated

- Azure Function App authentication is off

#### 1 policy updated for the IAM Security module

- AWS cross-account resource access through IAM policies

#### 2 compliance standards updated

- CIS v2.0.0 (Azure) Level 1
- CIS v2.0.0 (Azure) Level 2


## PCS-24.1.1 - 2024-1-16

### Added

#### 7 new policies

- AWS RDS database instance encrypted with Customer Managed Key (CMK) is not enabled for regular rotation
- AWS S3 bucket encrypted using Customer Managed Key (CMK) with overly permissive policy
- AWS S3 bucket encrypted with Customer Managed Key (CMK) is not enabled for regular rotation
- Azure AKS cluster configured with overly permissive API server access
- Azure Machine learning workspace configured with overly permissive network access
- Azure Storage account encryption key configured by access policy with privileged operations
- Azure Storage account encryption key is not rotated regularly

### Changed

#### 4 policies updated

- AWS Elasticsearch domain publicly accessible
- Azure Key Vault Firewall is not enabled 
- Azure Storage account is not configured with private endpoint connection
- GCP VM instance using a default service account with Cloud Platform access scope

#### 18 policies updated for the IAM Security module

- AWS EC2 Instance with AWS Organization management permissions
- AWS EC2 Instance with IAM policy management permissions
- AWS EC2 Instance with IAM write permissions
- AWS ECS Task Definition with AWS Organization management permissions
- AWS ECS Task Definition with IAM policy management permissions
- AWS ECS Task Definition with IAM write permissions
- AWS Elastic Beanstalk Platform with AWS Organization management permissions
- AWS Elastic Beanstalk Platform with IAM policy management permissions
- AWS Elastic Beanstalk Platform with IAM write permissions
- AWS IAM User with AWS Organization management permissions
- AWS IAM User with IAM policy management permissions
- AWS IAM User with IAM write permissions
- AWS Lambda Function with AWS Organization management permissions
- AWS Lambda Function with IAM policy management permissions
- AWS Lambda Function with IAM write permissions
- AWS Okta User with AWS Organization management permissions
- AWS Okta User with IAM policy management permissions
- AWS Okta User with IAM write permissions

### Removed

#### 3 policies deleted

- Azure storage account logging (Classic Diagnostic Setting) for blobs is disabled
- Azure storage account logging (Classic Diagnostic Setting) for queues is disabled
- Azure storage account logging (Classic Diagnostic Setting) for tables is disabled


## PCS-23.12.1 - 2023-12-04

### Added

#### 2 new compliance standards

- MITRE ATT&CK v13.0 Cloud IaaS for Enterprise
- MITRE ATT&CK v14.0 Cloud IaaS for Enterprise

### Changed

#### 16 policies updated for the IAM Security module

- AWS IAM policy allows Privilege escalation via PassRole & CodeBuild permissions
- AWS IAM policy allows Privilege escalation via PassRole & CodeStar project permissions
- AWS IAM policy allows Privilege escalation via PassRole & Data Pipeline permissions
- AWS IAM policy allows Privilege escalation via PassRole & EC2 permissions
- AWS IAM policy allows Privilege escalation via PassRole & Glue create job permissions
- AWS IAM policy allows Privilege escalation via PassRole & Glue development endpoint permissions
- AWS IAM policy allows Privilege escalation via PassRole & Glue update job permissions
- AWS IAM policy allows Privilege escalation via PassRole & Lambda create & invoke Function permissions
- AWS IAM policy allows Privilege escalation via PassRole & Lambda create Function & add permissions
- AWS IAM policy allows Privilege escalation via PassRole & Lambda create Function & Event source mapping permissions
- AWS IAM policy allows Privilege escalation via PassRole & SageMaker create notebook permissions
- AWS IAM policy allows Privilege escalation via PassRole & SageMaker create processing job permissions
- AWS IAM policy allows Privilege escalation via PassRole & SageMaker create training job permissions
- Azure VM instance associated managed identity with Azure built-in roles of Owner permissions
- GCP Compute Engine entities with predefined Admin roles
- GCP Compute Engine with IAM write access level


## PCS-23.11.1 - 2023-11-09

### Added

#### 4 new policies

- AWS EC2 instance that is internet reachable with unrestricted access (0.0.0.0/0) on ports 80/443
- Azure Virtual Machine (Linux) does not authenticate using SSH keys
- Azure Virtual Machine that is internet reachable with unrestricted access (0.0.0.0/0) on ports 80/443
- GCP VM instance that is internet reachable with unrestricted access (0.0.0.0/0) on ports 80/443

#### 1 new compliance standard

- Cybersecurity Maturity Model Certification (CMMC) v.2.0 (Level 2)

### Changed

#### 1 policy updated

- Azure Application Gateway is configured with SSL policy having TLS version 1.1 or lower

#### 2 policies updated for the IAM Security module

- GCP Compute Engine entities with predefined Admin roles
- GCP Compute Engine with IAM write access level 


## PCS-23.10.2 - 2023-10-24

### Changed

#### 1 policy updated

- GCP Kubernetes Engine Clusters have Network policy disabled

#### 1 policy updated for the IAM Security module

- AWS EC2 machine with write access permission to resource-based policies


## PCS-23.10.1 - 2023-10-12

### Added

#### 3 new policies

- Azure Storage account configured with Shared Key authorization
- Azure Storage account not configured with SAS expiration policy
- Azure Virtual machine configured with public IP and serial console access

### Changed

#### 11 policies updated

- Azure Activity log alert for Create or update network security group does not exist
- Azure Activity log alert for Create or update network security group rule does not exist
- Azure Activity log alert for Create or update security solution does not exist
- Azure Activity log alert for Create or update SQL server firewall rule does not exist
- Azure Activity log alert for Create policy assignment does not exist
- Azure Activity log alert for Delete network security group does not exist
- Azure Activity log alert for Delete network security group rule does not exist
- Azure Activity log alert for delete policy assignment does not exist
- Azure Activity log alert for Delete security solution does not exist 
- Azure Activity log alert for Delete SQL server firewall rule does not exist
- Azure Activity log alert for Update security policy does not exist


## PCS-23.9.2 - 2023-09-28

### Added

#### 1 new policies

- GCP backend bucket having dangling GCP Storage bucket

#### 2 new auto-remediation cli

- Azure App Services Remote debugging is enabled
- Azure Cosmos DB key based authentication is enabled

### Changed

#### 8 policies updated

- AWS S3 bucket accessible to unmonitored cloud accounts
- Azure Cache for Redis not configured with data in-transit encryption
- Azure Database for MariaDB not configured with private endpoint
- Azure Database for MySQL server not configured with private endpoint
- Azure log profile not capturing activity logs for all regions
- Azure PostgreSQL servers not configured with private endpoint
- Azure SQL Database server not configured with private endpoint
- GCP VPC Network subnets have Private Google access disabled


## PCS-23.9.1 - 2023-09-11

### Added

#### 7 new policies

- AWS CodeBuild project environment privileged mode is enabled
- AWS ECS services have automatic public IP address assignment enabled
- AWS Transit Gateway auto accept vpc attachment is enabled
- Azure Log analytics linked storage account is not configured with CMK encryption
- Azure Synapse Workspace vulnerability assessment is disabled
- GCP Cloud Function has risky basic role assigned
- GCP VM instance has risky basic role assigned

#### 19 new policies for the IAM Security module

- AWS EC2 IAM role with Elastic IP Hijacking permissions
- AWS EC2 machine with defense evasion impact of aws security services permissions
- AWS EC2 machine with write access permission to resource-based policies
- AWS EC2 with cloud log tampering permissions
- AWS EC2 with IAM role attached has credentials exposure permissions
- AWS EC2 with IAM role with alter critical configuration for s3 permissions
- AWS EC2 with write permission on critical configuration for s3
- AWS EC2 with write permissions on security group
- AWS IAM policy allows access and decrypt Secrets Manager Secrets permissions
- AWS Lambda with IAM role attached has credentials exposure permissions
- AWS Lambda with IAM role with Amazon RDS database SQL query execution permissions
- AWS Lambda with write permission on critical configuration for s3
- AWS Lambda with write permissions on security group
- AWS role having iam:PassRole and lambda:InvokeFunction permissions attached to EC2 instance
- EC2 with IAM role attached has iam:PassRole and ec2:Run Instances permissions
- GCP Cloud Function with permissions over Deployments Manager
- GCP Cloud Function with permissions to disrupt logging
- GCP VM instance with permissions over Deployments Manager
- GCP VM instance with permissions to disrupt logging

#### 1 new auto-remediation cli

- AWS EC2 instance not configured with Instance Metadata Service v2 (IMDSv2)

### Changed

#### 3 policies updated

- AWS Elastic Load Balancer v2 (ELBv2) with listener TLS/SSL is not configured
- Azure App Service Web app doesn't redirect HTTP to HTTPS
- GCP VM instance configured with default service account

#### 5 policy updated for the IAM Security module

- AWS S3 bucket with data destruction permissions is publicly accessible through IAM policies
- Azure AD users with broad Key Vault management access
- Azure Managed Identity (user assigned or system assigned) with broad Key Vault management access
- Azure Service Principals with broad Key Vault management access
- Azure VM instance associated managed identities with Key Vault management access (data access is not included)


## PCS-23.8.2 - 2023-08-16

### Added

#### 9 new policies

- AWS Auto Scaling group launch configuration configured with Instance Metadata Service hop count greater than 1
- AWS Auto Scaling group launch configuration has public IP address assignment enabled
- AWS Auto Scaling group launch configuration not configured with Instance Metadata Service v2 (IMDSv2)
- AWS Lambda function URL having overly permissive cross-origin resource sharing permissions
- Azure Cache for Redis not configured with data in-transit encryption
- Azure Database for MariaDB not configured private endpoint
- Azure Database for MySQL server not configured private endpoint
- Azure PostgreSQL servers not configured private endpoint
- Azure SQL Database server not configured private endpoint

#### 2 new compliance standards

- CIS v2.0.0 (AWS) - Level 1
- CIS v2.0.0 (AWS) - Level 2

### Changed

#### 5 policies updated

- AWS CloudTrail is not enabled with multi trail and not capturing all management events
- Azure storage account logging (Classic Diagnostic Setting) for blobs is disabled
- Azure storage account logging (Classic Diagnostic Setting) for queues is disabled
- Azure storage account logging (Classic Diagnostic Setting) for tables is disabled
- GCP VM instances have block project-wide SSH keys feature disabled


## PCS-23.8.1 - 2023-08-02

### Added

#### 5 new policies

- AWS Route53 Hosted Zone having dangling DNS record with subdomain takeover risk associated with AWS Elastic Beanstalk Instance
- Azure App Service web apps with public network access
- Azure Data Explorer cluster disk encryption is disabled
- Azure Data Explorer cluster double encryption is disabled
- Azure Function app configured with public network access

### Changed

#### 1 policy updated

- GCP VPC Flow logs for the subnet is set to Off

#### 1 auto-remediation cli updated

- Azure MySQL database flexible server SSL enforcement is disabled

#### 1 policy updated for the IAM Security module

- EC2 with IAM role attached has s3:GetObject and s3:ListBucket permissions

#### 3 compliance standards updated

- CIS v2.0.0 (Azure) Level 1
- CIS v2.0.0 (Azure) Level 2
- Otoritas Jasa Keuangan (OJK) 38 POJK.03 2016


## PCS-23.7.2 - 2023-07-17

### Added

#### 1 new compliance standard

- MLPS 2.0 (Level 3)

#### 3 new policies for the IAM Security module

- AWS EC2 with IAM role with destruction permissions for Amazon RDS databases
- AWS EC2 with IAM role with destruction permissions for AWS Key Management Service (KMS)
- AWS Lambda with IAM role with destruction permissions for Amazon RDS databases

### Changed

#### 4 policies updated

- AWS Elastic Load Balancer v2 (ELBv2) with listener TLS/SSL is not configured
- AWS Route53 Hosted Zone having dangling DNS record with subdomain takeover risk associated with AWS S3 Bucket
- AWS Secret Manager Automatic Key Rotation is not enabled
- OCI Block Storage Block Volume does not have backup enabled

#### 19 policies updated for the IAM Security module

- AWS IAM policy allows Privilege escalation via Codestar create project and associate team member permissions
- AWS IAM policy allows Privilege escalation via EC2 describe and SSM list and send command permissions
- AWS IAM policy allows Privilege escalation via EC2 describe and SSM session permissions
- AWS IAM policy allows Privilege escalation via EC2 Instance Connect permissions
- AWS IAM policy allows Privilege escalation via Glue Dev Endpoint permissions
- AWS IAM policy allows Privilege escalation via PassRole & CloudFormation stack permissions
- AWS IAM policy allows Privilege escalation via PassRole & CodeBuild permissions
- AWS IAM policy allows Privilege escalation via PassRole & CodeStar project permissions
- AWS IAM policy allows Privilege escalation via PassRole & Data Pipeline permissions
- AWS IAM policy allows Privilege escalation via PassRole & EC2 permissions
- AWS IAM policy allows Privilege escalation via PassRole & Glue create job permissions
- AWS IAM policy allows Privilege escalation via PassRole & Glue development endpoint permissions
- AWS IAM policy allows Privilege escalation via PassRole & Glue update job permissions
- AWS IAM policy allows Privilege escalation via PassRole & Lambda create & invoke Function permissions
- AWS IAM policy allows Privilege escalation via PassRole & Lambda create Function & add permissions
- AWS IAM policy allows Privilege escalation via PassRole & Lambda create Function & Event source mapping permissions
- AWS IAM policy allows Privilege escalation via PassRole & SageMaker create notebook permissions
- AWS IAM policy allows Privilege escalation via PassRole & SageMaker create processing job permissions
- AWS IAM policy allows Privilege escalation via PassRole & SageMaker create training job permissions


## PCS-23.7.1 - 2023-07-10

### Added

#### 2 new policies

- AWS Route53 Hosted Zone having dangling DNS record with subdomain takeover risk
- Azure SQL on Virtual Machine (Linux) with basic authentication

#### 1 new compliance standard

- Otoritas Jasa Keuangan (OJK) 38 POJK.03 2016

#### 4 new policies for the IAM Security module

- AWS EC2 instance with database management write access permissions
- AWS S3 bucket with data destruction permissions is publicly accessible through IAM policies
- Azure VM instance with database management write access permissions
- GCP VM instance with database management write access permissions

### Changed

#### 3 policies updated

- AWS Application Load Balancer (ALB) is not using the latest predefined security policy
- AWS EC2 instance that is reachable from untrust internet source to ports with high risk
- Azure SQL Server ADS Vulnerability Assessment is disabled


## PCS-23.6.2 - 2023-06-22

### Added

#### 1 new policy

- GCP VM instance that is reachable from untrust internet source to ports with high risk

### Changed

#### 1 policy updated

- AWS S3 buckets are accessible to public via ACL


## PCS-23.6.1 - 2023-06-06

### Added

#### 4 new policies

- AWS EC2 instance that is internet reachable with unrestricted access (0.0.0.0/0) to Admin ports
- AWS EC2 instance that is reachable from untrust internet source to ports with high risk
- Azure Virtual Machine that is internet reachable with unrestricted access (0.0.0.0/0) to Admin ports
- GCP VM instance that is internet reachable with unrestricted access (0.0.0.0/0) to Admin ports

#### 2 new compliance standards

- CIS v1.4.0 (GKE) - Level 1
- CIS v1.4.0 (GKE) - Level 2

#### 2 policies for the IAM Security module

- EC2 with IAM role attached has s3:GetObject permission
- Azure VM instance with risky Storage account permissions

### Changed

#### 7 policies updated

- AWS S3 bucket policy overly permissive to any principal
- AWS S3 bucket publicly writable
- GCP Log metric filter and alert does not exist for Cloud Storage IAM permission changes
- GCP Log metric filter and alert does not exist for VPC network route changes
- GCP Log metric filter and alert does not exist for VPC network route delete and insert
- GCP Log metric filter and alert does not exist for VPC network changes
- GCP Log metric filter and alert does not exist for VPC network route patch and insert


## PCS-23.5.2 - 2023-05-22

### Added

#### 3 new policies

- Azure SQL Server (PaaS) reachable from any untrust internet source
- Azure Virtual Machine reachable from any untrust internet source to ports with high risk
- GCP VM instance that is internet reachable with unrestricted access (0.0.0.0/0)

### Changed

#### 2 policies updated

- AWS S3 bucket is not configured with MFA Delete
- Azure Virtual Machine in running state that is internet reachable with unrestricted access (0.0.0.0/0)


## PCS-23.5.1 - 2023-05-08

### Added

#### 3 new compliance standards

- CIS v2.0.0 (Azure) Level 1
- CRI Profile v1.2.1
- MITRE ATT&CK v12

#### 9 new policies for the IAM Security module

- AWS Lambda Function with data destruction permissions
- Azure AD users with Key Vault access through Build-in Azure roles
- Azure Managed Identity (user assigned or system assigned) with Key Vault access through Build-in Azure roles
- Azure Service Principals with Key Vault access through Build-in Azure roles
- Azure Service Principals with Key Vault management access
- Azure VM associated with entities that have risky permissions
- Azure VM instance associated managed identities with Key Vault management access (data access is not included)
- Azure VM instance associated managed identity with Azure built-in roles of Contributor/Owner permissions
- Azure VM instance with Run command or Custom script execution permissions 

### Changed

#### 1 policy updated

- GCP Kubernetes Engine Clusters have Master authorized networks disabled

#### 2 policies updated for the IAM Security module

- Azure AD users with Key Vault management access
- Azure Managed Identity (user assigned or system assigned) with Key Vault management access

### Removed

#### 3 policies deleted

- GCP Kubernetes cluster istioConfig not enabled
- GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled
- GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled


## PCS-23.4.2 - 2023-04-24

### Added

#### 9 new policies for the IAM Security module

- AWS EC2 instance with creation of new Group with attach policy permission
- AWS EC2 instance with creation of new Role with attach policy permission
- AWS EC2 instance with creation of new User with attach policy permission
- AWS EC2 instance with data destruction permissions
- AWS EC2 instance with privilege escalation risk permissions
- Azure VM instance with data destruction permissions
- GCP VM instance with data destruction permissions
- GCP VM instance with permissions to impersonate a service account
- GCP VM instance with write permissions on deny policies


## PCS-23.4.1 - 2023-04-10

### Added

#### 19 new policies for the IAM Security module

- AWS IAM policy allows Privilege escalation via Codestar create project and associate team member permissions
- AWS IAM policy allows Privilege escalation via EC2 describe and SSM list and send command permissions
- AWS IAM policy allows Privilege escalation via EC2 describe and SSM session permissions
- AWS IAM policy allows Privilege escalation via EC2 Instance Connect permissions
- AWS IAM policy allows Privilege escalation via Glue Dev Endpoint permissions
- AWS IAM policy allows Privilege escalation via PassRole & CloudFormation stack permissions
- AWS IAM policy allows Privilege escalation via PassRole & CodeBuild permissions
- AWS IAM policy allows Privilege escalation via PassRole & CodeStar project permissions
- AWS IAM policy allows Privilege escalation via PassRole & Data Pipeline permissions
- AWS IAM policy allows Privilege escalation via PassRole & EC2 permissions
- AWS IAM policy allows Privilege escalation via PassRole & Glue create job permissions
- AWS IAM policy allows Privilege escalation via PassRole & Glue development endpoint permissions
- AWS IAM policy allows Privilege escalation via PassRole & Glue update job permissions
- AWS IAM policy allows Privilege escalation via PassRole & Lambda create & invoke Function permissions
- AWS IAM policy allows Privilege escalation via PassRole & Lambda create Function & add permissions
- AWS IAM policy allows Privilege escalation via PassRole & Lambda create Function & Event source mapping permissions
- AWS IAM policy allows Privilege escalation via PassRole & SageMaker create notebook permissions
- AWS IAM policy allows Privilege escalation via PassRole & SageMaker create processing job permissions
- AWS IAM policy allows Privilege escalation via PassRole & SageMaker create training job permissions

#### 1 new compliance standard

- ISO/IEC 27001:2022

### Changed

#### 633 policies updated

- Policy Severity updated for 633 system default policies:
- https://docs.paloaltonetworks.com/content/dam/techdocs/en_US/pdf/prisma/prisma-cloud/prerelease/policy-severity-level-changes.csv

#### 3 compliance standards updated

- CIS v1.2.0 (GCP)
- CIS v1.3.0 (GCP)
- CIS v2.0.0 (GCP) Level 2


## PCS-23.3.2 - 2023-03-27

### Added

#### 1 new compliance standard

- ISO 27002:2022

### Changed

#### 4 policies updated

- AWS access keys not used for more than 45 days
- AWS Cloudfront Distribution with S3 have Origin Access set to disabled
- AWS EKS cluster endpoint access publicly enabled
- GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)


## PCS-23.3.1 - 2023-03-13

### Added

#### 1 new compliance standard

- CSA CCM v.4.0.6 

### Changed

#### 4 policies updated

- GCP HTTPS Load balancer is configured with SSL policy having TLS version 1.1 or lower
- GCP HTTPS Load balancer SSL Policy not using restrictive profile
- GCP Load Balancer HTTPS proxy permits SSL policies with weak cipher suites
- GCP Load Balancer SSL proxy permits SSL policies with weak cipher suites


## PCS-23.2.2 - 2023-02-28

### Added

#### 2 new policies

- Azure AKS cluster is not configured with disk encryption set
- Azure Service Fabric cluster not configured with cluster protection level security

### Changed

#### 7 policies updated

- AWS EC2 instance that is internet reachable with unrestricted access (0.0.0.0/0)
- AWS Glue connection do not have SSL configured
- Azure Virtual Network subnet is not configured with a Network Security Group
- GCP Storage buckets are publicly accessible to all authenticated users
- GCP Storage buckets are publicly accessible to all users
- GCP Storage log buckets have object versioning disabled
- GCP VPC Network subnets have Private Google access disabled

#### 1 compliance standard updated

- AWS Foundational Security Best Practices standard


## PCS-23.2.1 - 2023-02-13

### Added

#### 5 new policies

- AWS CloudFront distributions does not have a default root object configured
- AWS SSM documents are public
- Azure Microsoft Defender for Cloud set to Off for Resource Manager
- Azure Storage account is not configured with private endpoint connection
- GCP SQL server instance database flag 3625 (trace flag) is not set to on

### Changed

#### 9 policies updated

- AWS Certificate Manager (ACM) has invalid or failed certificate
- AWS CloudTrail trail logs is not integrated with CloudWatch Log
- AWS ECS Fargate task definition root user found
- AWS S3 buckets with configurations set to host websites
- Azure Activity Log retention should not be set to less than 365 days
- Azure Container Registry does not use a dedicated resource group
- Azure Storage account container storing activity logs is publicly accessible
- GCP SQL Instances do not have valid SSL configuration
- GCP SQL MySQL DB instance point-in-time recovery backup (Binary logs) is not enabled


## PCS-23.1.2 - 2023-02-01

### Added

#### 5 new compliance standards

- CIS v1.3.0 (GKE) - Level 1
- CIS v1.3.0 (GKE) - Level 2
- CIS v2.0.0 (GCP) Level 1
- CIS v2.0.0 (GCP) Level 2
- Sarbanes Oxley Act (SOX)

### Changed

#### 27 policies updated

- AWS ALB attached WAFv2 WebACL is not configured with AMR for Log4j Vulnerability
- AWS API Gateway Rest API attached WAFv2 WebACL is not configured with AMR for Log4j Vulnerability
- AWS AppSync attached WAFv2 WebACL is not configured with AMR for Log4j Vulnerability
- AWS CloudFront attached WAFv2 WebACL is not configured with AMR for Log4j Vulnerability
- AWS CloudFront viewer protocol policy is not configured with HTTPS
- Azure Activity log alert for Create or update network security group does not exist
- Azure Activity log alert for Create or update network security group rule does not exist
- Azure Activity log alert for Create or update security solution does not exist
- Azure Activity log alert for Create or update SQL server firewall rule does not exist
- Azure Activity log alert for Create policy assignment does not exist
- Azure Activity log alert for Delete network security group does not exist
- Azure Activity log alert for Delete network security group rule does not exist
- Azure Activity log alert for delete policy assignment does not exist
- Azure Activity log alert for Delete security solution does not exist
- Azure Activity log alert for Delete SQL server firewall rule does not exist
- Azure Activity log alert for Update security policy does not exist
- Azure log profile not capturing activity logs for all regions
- Azure Microsoft Defender for Cloud automatic provisioning of log Analytics agent for Azure VMs is set to Off
- Azure SQL Server allow access to any Azure internal resources
- Azure Storage Account 'Trusted Microsoft Services' access not enabled
- Azure storage account has a blob container with public access
- Azure storage account logging for queues is disabled
- Azure Storage account soft delete is disabled
- Azure Storage Account without Secure transfer enabled
- Azure Storage accounts soft delete is disabled
- Azure subscriptions with custom roles are overly permissive
- OCI MFA is disabled for IAM users


## PCS-23.1.1 - 2023-01-17

### Changed

#### 13 policies updated

- Azure AD Users can consent to apps accessing company data on their behalf is enabled
- Azure Monitoring log profile is not configured to export activity logs
- Azure SQL server not configured with Active Directory admin authentication
- Azure Service bus namespace not configured with Azure Active Directory (Azure AD) authentication
- Azure Storage Account default network access is set to 'Allow'
- Azure Virtual Network subnet is not configured with a Network Security Group
- GCP Bucket containing Operations Suite Logs have bucket logging disabled
- GCP Kubernetes Engine Clusters have Cloud Logging disabled
- GCP Kubernetes Engine Clusters have Cloud Monitoring disabled
- GCP Kubernetes Engine Clusters have Legacy Authorization enabled
- GCP Kubernetes Engine Clusters not configured with network traffic egress metering
- GCP Log metric filter and alert does not exist for Project Ownership assignments/changes
- GCP User managed service accounts have user managed service account keys

### Removed

#### 3 policy deleted

- AWS EC2 instance is not configured with VPC
- AWS VPC Security group nearing availability limit
- AWS VPC Subnets nearing availability limit

#### 1 auto-remediation cli removed

- GCP Kubernetes Engine Clusters have Legacy Authorization enabled


## PCS-22.12.1 - 2022-12-05

### Added

#### 13 new policies

- Azure Cosmos DB (PaaS) instance reachable from untrust internet source
- Instance affected by Apache Log4j denial of service vulnerability is exposed to network traffic from the internet [CVE-2021-45105]
- Instance affected by Apache Log4j JDBC Appender remote code execution vulnerability is exposed to network traffic from the internet [CVE-2021-44832]
- Instance affected by Apache Log4j Thread Context Map remote code execution vulnerability is exposed to network traffic from the internet [CVE-2021-45046]
- Instance affected by Argo CD vulnerability is exposed to network traffic from the internet [CVE-2022-24348]
- Instance affected by Dirty Pipe vulnerability is exposed to network traffic from the internet [CVE-2022-0847]
- Instance affected by Java Psychic Signatures vulnerability is exposed to network traffic from the internet [CVE-2022-21449]
- Instance affected by Linux kernel container escape vulnerability is exposed to network traffic from the internet [CVE-2022-0185]
- Instance affected by OpenSSL X.509 email address 4-Byte BOF (Spooky SSL) vulnerability is exposed to network traffic from the internet [CVE-2022-3602]
- Instance affected by Samba vfs_fruit module remote code execution vulnerability is exposed to network traffic from the internet [CVE-2021-44142]
- Instance affected by SMB DCE/RPC remote code execution vulnerability is exposed to network traffic from the internet [CVE-2022-26809]
- Instance affected by Spring Cloud Function SpringShell vulnerability is exposed to network traffic from the internet [CVE-2022-22963]
- Instance affected by Text2shell RCE vulnerability is exposed to network traffic from the internet [CVE-2022-42889]

#### 2 new compliance standards

- Multi-Level Protection Scheme 2.0 (Level 2)
- Secure Controls Framework (SCF) - 2022.2.1

### Changed

#### 14 policies updated

- AWS Customer Master Key (CMK) rotation is not enabled
- AWS IAM Roles with Administrator Access Permissions
- Azure App Service Web app doesn't use latest Java version
- Azure Network Security Group allows all traffic on Telnet (TCP Port 23)
- GCP Log metric filter and alert does not exist for Audit Configuration Changes
- GCP Log metric filter and alert does not exist for Cloud Storage IAM permission changes
- GCP Log metric filter and alert does not exist for IAM custom role changes
- GCP Log metric filter and alert does not exist for SQL instance configuration changes
- GCP Log metric filter and alert does not exist for VPC network changes
- GCP Log metric filter and alert does not exist for VPC Network Firewall rule changes
- GCP Log metric filter and alert does not exist for VPC network route changes
- Instance affected by Apache Log4j vulnerability is exposed to network traffic from the internet [CVE-2021-44228]
- Instance affected by OMIGOD vulnerability is exposed to network traffic from the internet
- Instance affected by SpringShell vulnerability is exposed to network traffic from the internet


## PCS-22.11.1 - 2022-11-07

### Added

#### 2 new policies

- GCP API key is created for a project
- GCP Identity-Aware Proxy (IAP) not enabled for External HTTP(s) Load Balancer

### Changed

#### 15 policies updated

- AWS RDS minor upgrades not enabled
- AWS S3 bucket accessible to unmonitored cloud accounts
- AWS VPC gateway endpoint policy is overly permissive
- Azure AKS cluster Azure CNI networking not enabled
- Azure AKS cluster HTTP application routing enabled
- Azure AKS cluster monitoring not enabled
- Azure AKS cluster pool profile count contains less than 3 nodes
- Azure AKS enable role-based access control (RBAC) not enforced
- Azure Front Door does not have the Azure Web application firewall (WAF) enabled
- Azure SQL Database with Auditing Retention less than 90 days
- GCP Kubernetes Engine Clusters have binary authorization disabled
- GCP Kubernetes Engine Clusters have Cloud Monitoring disabled
- GCP PostgreSQL instance database flag log_statement is not set appropriately
- GCP Storage Buckets with publicly accessible GCP logs
- GCP Storage log buckets have object versioning disabled

#### 9 policies updated for the IAM Security module

- AWS EC2 instance with IAM write access leve
- AWS EC2 instance with IAM permissions management access level
- AWS IAM effective permissions are over-privileged (90 days)
- AWS cross-account resource access through IAM policies
- GCP entities with permissions to impersonate a service account in another project
- GCP users with 'Owner' role on org level
- GCP service accounts with 'Owner' role on org level
- GCP IAM effective permissions are over-privileged (90 days)
- Azure IAM effective permissions are over-privileged (90 days)


## PCS-22.9.2 - 2022-09-27

### Added

#### 8 new policies

- AWS ElastiCache Memcached cluster with in-transit encryption disabled
- Azure SQL server Transparent Data Encryption (TDE) encryption disabled
- Azure VM data disk is not configured with any encryption
- Azure VM OS disk is not configured with any encryption
- GCP Cloud Run service is publicly accessible
- GCP KMS crypto key is anonymously accessible
- GCP Log metric filter and alert does not exist for VPC network route delete and insert
- GCP Log metric filter and alert does not exist for VPC network route patch and insert

#### 7 new compliance standard

- CIS v1.5.0 (AWS) - Level 1
- CIS v1.5.0 (AWS) - Level 2
- CIS v1.5.0 (Azure) - Level 1
- CIS v1.5.0 (Azure) - Level 2
- Fedramp (Low)
- Fedramp (Moderate)
- Korea – Information Security Management System (ISMS)

### Changed

#### 13 policies updated

- Azure App Service Web app client certificate is disable
- Azure App Service Web app doesn't use latest .Net Core version
- Azure App Service Web app doesn't use latest PHP version
- Azure App Service Web app doesn't use latest Python version
- Azure Function App authentication is off
- Azure Function App client certificate is disabled
- Azure Function App doesn't have a Managed Service Identity
- Azure Function App doesn't redirect HTTP to HTTPS
- Azure Function App doesn't use HTTP 2.0
- Azure Function App doesn't use latest TLS version
- Azure Resource Group does not have a resource lock
- Azure SQL Server audit log retention is less than 91 days
- Azure SQL server TDE protector is not encrypted with BYOK (Use your own key)


## PCS-22.9.1 - 2022-09-13

### Added

#### 6 new policies

- AWS SQS Queue not configured with server side encryption
- Azure MySQL (PaaS) instance reachable from untrust internet source on TCP port 3306
- Azure PostgreSQL (PaaS) instance reachable from untrust internet source on TCP port 5432
- Azure VM instance in running state that is internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port
- GCP BigQuery Dataset not configured with default CMEK
- GCP Cloud Function is publicly accessible

#### 11 new policies for the IAM Security module

- Azure AD user with permissions to manage Azure permissions broadly that was not used in the last 90 days
- Azure AD user with the Azure built-in roles of Contributor
- Azure AD user with the Azure built-in roles of Owner
- Azure AD user with the Azure built-in roles of Reader
- Azure AD users with Key Vault access
- Azure Managed Identity (user assigned or system assigned) with Key Vault access
- Azure Managed Identity (user assigned or system assigned) with the Azure built-in roles of Contributor
- Azure Managed Identity (user assigned or system assigned) with the Azure built-in roles of Owner
- Azure Managed Identity (user assigned or system assigned) with the Azure built-in roles of Reader
- Azure Managed Identity with permissions to manage Azure permissions broadly that was unused in the last 90 days
- Azure Managed Identity with permissions to other subscriptions

### Changed

#### 8 policies updated

- AWS CloudFront web distribution using insecure TLS version
- AWS ElastiCache Redis with in-transit encryption disabled (Non-replication group)
- AWS RDS minor upgrades not enabled
- AWS SNS topic policy overly permissive for publishing
- Azure Container Instance is not configured with virtual network
- GCP Kubernetes Engine Clusters have Binary authorization disabled
- GCP Log bucket retention policy is not configured using bucket lock
- GCP PostgreSQL instance database flag log_connections is disabled

#### 3 compliance standard updated

- ACSC Information Security Manual (ISM)
- Australian Cyber Security Centre (ACSC) Essential Eight
- Australian Energy Sector Cyber Security Framework (AESCSF)


## PCS-22.8.2 - 2022-08-31

### Added

#### 1 new compliance standard

- CIS Google Kubernetes Engine (GKE) v1.2.0

### Changed

#### 2 policies updated

- AWS EKS cluster security group overly permissive to all traffic
- AWS Lambda function managed ENI reachable from any untrust internet source

### Removed

#### 1 policy deleted

- GCP Kubernetes Engine Clusters have pod security policy disabled


## PCS-22.8.1 - 2022-08-17

### Added

#### 13 new policies

- AWS DocumentDB cluster deletion protection is disabled
- AWS Lambda function URL AuthType set to NONE
- AWS Neptune Cluster not configured with IAM authentication
- AWS Neptune cluster deletion protection is disabled
- AWS Web Application Firewall (AWS WAF) Classic logging is disabled
- AWS Web Application Firewall v2 (AWS WAFv2) logging is disabled
- Azure Batch account is not configured with managed identity
- Azure Service bus namespace not configured with Azure Active Directory (Azure AD) authentication
- Azure Virtual Machine (Windows) secure boot feature is disabled
- Azure Virtual Machine vTPM feature is disabled
- OCI Kubernetes Engine Cluster boot volume is not configured with in-transit data encryption
- OCI Kubernetes Engine Cluster endpoint is not configured with Network Security Groups
- OCI Kubernetes Engine Cluster pod security policy not enforced

#### 3 new compliance standards

- Cybersecurity Maturity Model Certification (CMMC) v.2.0 (Level 1)
- HITRUST CSF v.9.6.0
- New York Department of Financial Services (NYDFS) 23 Codes, Rules and Regulations (Part 500)

### Changed

#### 4 policies updated

- Azure Key Vault Key has no expiration date (Non-RBAC Key vault)
- Azure Key Vault key has no expiration date (RBAC Key vault)
- Azure Key Vault secret has no expiration date (Non-RBAC Key vault)
- Azure Key Vault secret has no expiration date (RBAC Key vault)


## PCS-22.7.2 - 2022-08-03

### Added

#### 15 new policies

- AWS Classic Load Balancer not configured to span multiple Availability Zones
- AWS ECR Repository not configured with a lifecycle policy
- AWS EKS cluster public endpoint access overly permissive to all traffic
- AWS Kinesis Firehose with Direct PUT as source has SSE encryption disabled
- AWS OpenSearch attached security group overly permissive to all traffic
- AWS OpenSearch node-to-node encryption is disabled
- AWS Secret Manager Automatic Key Rotation is not enabled
- Azure Automation account configured with overly permissive network access
- Azure Automation account is not configured with managed identity
- Azure Automation account variables are not encrypted
- Azure Data Factory (V2) configured with overly permissive network access
- Azure Data Factory (V2) is not configured with managed identity
- Azure PostgreSQL database flexible server configured with overly permissive network access
- Azure PostgreSQL database server deny public network access setting is not set
- Azure Virtual network not protected by DDoS Protection Standard

#### 2 new compliance standards

- CIS v1.2.0 (OCI)
- CIS v1.3.0 (GCP)

#### 17 new policies for the IAM Security module

- GCP Compute Engine entities with predefined Admin roles
- GCP Compute Engine with IAM write access level
- GCP entities with permissions to impersonate a service account in another project
- GCP IAM effective permissions are over-privileged (7 days)
- GCP IAM effective permissions are over-privileged (90 days)
- GCP service accounts with 'Editor' role on folder level
- GCP service accounts with 'Editor' role on org level 
- GCP service accounts with 'Owner' role on folder level 
- GCP service accounts with 'Owner' role on org level 
- GCP service accounts with permissions to deploy new resources
- GCP User with IAM write access level permissions
- GCP users with 'Editor' role on folder level 
- GCP users with 'Editor' role on org level 
- GCP users with 'Owner' role on folder level 
- GCP users with 'Owner' role on org level
- GCP users with permissions to deploy new resources
- GCP users with Service Account Token Creator role


## PCS-22.7.1 HotFix - 2022-07-25

### Added

#### 1 new policy

- GCP KMS Symmetric key not rotating in every 90 days

### Removed

#### 1 policy deleted

- GCP KMS encryption key not rotating in every 90 days


## PCS-22.7.1 - 2022-07-19

### Added

#### 3 new policies

- AWS Lambda function managed ENI reachable from any untrust internet source
- AWS S3 bucket policy does not enforce HTTPS request only
- AWS S3 bucket access control lists (ACLs) in use

#### 4 new compliance standards

- CIS Critical Security Controls V7.1
- CIS Critical Security Controls V8
- Federal Financial Institutions Examination Council (FFIEC)
- Payment Card Industry Data Security Standard (PCI DSS v4.0)

### Changed

#### 8 policies updated

- AWS IAM Groups with administrator access permissions
- Azure Cosmos DB allows traffic from public Azure datacenters
- Azure Microsoft Defender for Cloud security alert email notifications is not set
- Azure Microsoft Defender for Cloud security contact additional email is not set
- Azure PostgreSQL Database Server 'Allow access to Azure services' enabled
- Azure PostgreSQL Database Server Firewall rule allow access to all IPV4 address
- Azure SQL Server allow access to any Azure internal resources
- Azure SQL Servers Firewall rule allow access to all IPV4 address


## PCS-22.6.3 - 2022-07-06

### Added

#### 6 new policies

- AWS DocumentDB Cluster is not enabled with data encryption in transit
- AWS IAM policy attached to AWS Lambda execution role is overly permissive
- AWS Lambda execution role having overly permissive inline policy
- Azure Microsoft Defender for Cloud set to Off for DNS
- GCP Load Balancer HTTPS proxy permits SSL policies with weak cipher suites
- GCP Load Balancer SSL proxy permits SSL policies with weak cipher suites

### Changed

#### 9 policies updated

- Azure Microsoft Defender for Cloud JIT network access monitoring is set to disable
- Azure Microsoft Defender for Cloud adaptive application controls monitoring is set to disabled
- Azure Microsoft Defender for Cloud disk encryption monitoring is set to disabled
- Azure Microsoft Defender for Cloud email notification for subscription owner is not set
- Azure Microsoft Defender for Cloud endpoint protection monitoring is set to disabled
- Azure Microsoft Defender for Cloud security configurations monitoring is set to disabled
- Azure Microsoft Defender for Cloud security contact phone number is not set
- Azure Microsoft Defender for Cloud system updates monitoring is set to disabled
- GCP HTTPS Load balancer is configured with SSL policy having TLS version 1.1 or lower


## PCS-22.6.2 - 2022-06-21

### Added

#### 3 new policies

- AWS Lambda Function resource-based policy is overly permissive
- Azure MySQL database flexible server SSL enforcement is disabled
- Azure MySQL database flexible server using insecure TLS version

#### 2 new auto-remediation cli's

- AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled
- Azure MySQL database flexible server SSL enforcement is disabled

### Changed

#### 20 policies updated

- AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled
- AWS Customer Master Key (CMK) rotation is not enabled
- AWS Lambda function communicating with ports known to mine Monero
- AWS Network Load Balancer (NLB) is not using the latest predefined security policy
- AWS RDS instance with copy tags to snapshots disabled
- Azure Application Gateway is configured with SSL policy having TLS version 1.1 or lower
- GCP Firewall rule allows all traffic on DNS port (53)
- GCP Firewall rule allows all traffic on FTP port (21)
- GCP Firewall rule allows all traffic on Microsoft-DS port (445)
- GCP Firewall rule allows all traffic on MongoDB port (27017)
- GCP Firewall rule allows all traffic on MySQL DB port (3306)
- GCP Firewall rule allows all traffic on NetBIOS-SSN port (139)
- GCP Firewall rule allows all traffic on Oracle DB port (1521)
- GCP Firewall rule allows all traffic on POP3 port (110)
- GCP Firewall rule allows all traffic on PostgreSQL port (5432)
- GCP Firewall rule allows all traffic on RDP port (3389)
- GCP Firewall rule allows all traffic on SMTP port (25)
- GCP Firewall rule allows all traffic on SSH port (22)
- GCP Firewall rule allows inbound traffic from anywhere with no specific target set
- GCP Firewall with Inbound rule overly permissive to All Traffic

#### 8 policies updated for the IAM Security module

- AWS ECR Repository that is publicly accessible through IAM policies
- AWS KMS Key that is publicly accessible through IAM policies
- AWS Lambda Function that is publicly accessible through IAM policies
- AWS Lambda Layer Version that is publicly accessible through IAM policies
- AWS S3 bucket that is publicly accessible through IAM policies
- AWS SNS Topic that is publicly accessible through IAM policies
- AWS SQS Queue that is publicly accessible through IAM policies
- AWS Secret Manager Secret that is publicly accessible through IAM policies


## PCS-22.6.1 - 2022-06-07

### Added

#### 3 new compliance standards

- ACSC Information Security Manual (ISM)
- Australian Cyber Security Centre (ACSC) Essential Eight
- Australian Energy Sector Cyber Security Framework (AESCSF)

### Changed

#### 1 policy updated for the IAM Security module

- AWS KMS Key that is publicly accessible through IAM policies

#### 1 compliance standard updated

- New Zealand Information Security Manual (NZISM v3.4)


## PCS-22.5.2 - 2022-05-24

### Added

#### 3 new policies

- AWS IAM Policy permission may cause privilege escalation
- Azure Spring Cloud service is not configured with virtual network
- Azure Virtual Desktop session host is not configured with managed identity

#### 2 new auto-remediation cli's

- GCP Firewall rule allows all traffic on HTTP port (80)
- GCP Firewall rule allows all traffic on Telnet port (23)

### Changed

#### 2 policies updated

- GCP Firewall rule allows all traffic on HTTP port (80)
- GCP Firewall rule allows all traffic on Telnet port (23)


## PCS-22.5.1 - 2022-05-10

### Added

#### 7 new policies

- AWS Aurora PostgreSQL exposed to local file read vulnerability
- AWS IAM policy overly permissive to Lambda service
- AWS Lambda IAM policy overly permissive to all traffic
- AWS Lambda function communicating with ports known to mine Monero
- AWS RDS PostgreSQL exposed to local file read vulnerability
- Azure Recovery Services vault is not configured with managed identity
- GCP Firewall rule exposes GKE clusters by allowing all traffic on port 10250

#### 1 new auto-remediation cli

- GCP Firewall rule exposes GKE clusters by allowing all traffic on port 10250

### Changed

#### 10 policies updated

- AWS EMR cluster is not enabled with local disk encryption using Custom key provider
- AWS Network Load Balancer (NLB) is not using the latest predefined security policy
- Azure SQL Databases with disabled Email service and co-administrators for Threat Detection
- Azure SQL Server ADS Vulnerability Assessment 'Also send email notifications to admins and subscription owners' is disabled
- Azure SQL Server ADS Vulnerability Assessment 'Send scan reports to' is not configured
- Azure SQL Server ADS Vulnerability Assessment Periodic recurring scans is disabled
- Azure SQL Server ADS Vulnerability Assessment is disabled
- Azure SQL databases Defender setting is set to Off
- Azure SQL server Defender setting is set to Off
- GCP User managed service accounts have user managed service account keys

### Removed

#### 5 policies deleted

- Azure SQL Database with Threat Retention less than or equals to 90 days
- Azure SQL Server threat detection alerts not enabled for all threat types
- Azure SQL Server threat logs retention is less than 91 days
- Send alerts on field value on SQL Databases is misconfigured
- Threat Detection types on SQL databases is misconfigured


## PCS-22.4.2 - 2022-04-25

### Added

#### 3 new policies

- Azure Service bus namespace configured with overly permissive network access
- GCP VPC network not configured with DNS policy with logging enabled
- Instance affected by OMIGOD vulnerability is exposed to network traffic from the internet

#### 1 new auto-remediation cli

- GCP Kubernetes Engine Clusters have Master authorized networks disabled

### Changed

#### 2 policies updated

- AWS API gateway request parameter is not validated
- GCP Kubernetes Engine Clusters have Master authorized networks disabled


## PCS-22.4.1 - 2022-04-11

### Added

#### 3 new policies

- Azure Microsoft Defender for Cloud set to Off for Containers
- GCP Firewall rule exposes GKE clusters by allowing all traffic on read-only port (10255)
- Instance affected by SpringShell vulnerability is exposed to network traffic from the internet

#### 1 new auto-remediation cli

- GCP Firewall rule exposes GKE clusters by allowing all traffic on read-only port (10255)

### Changed

#### 4 policies updated

- Azure Security Center Defender plans is set to Off
- GCP BigQuery dataset is publicly accessible
- GCP GCR Container Vulnerability Scanning is disabled
- GCP VM instance with the external IP address

### Removed

#### 2 policies deleted

- Azure Microsoft Defender for Cloud is set to Off for Container Registries
- Azure Microsoft Defender for Cloud is set to Off for Kubernetes


## PCS-22.3.2 - 2022-03-28

### Added

#### 4 new policies

- AWS IAM Access analyzer is not configured
- Azure Spring Cloud App system-assigned managed identity is disabled
- Azure Spring Cloud app end-to-end TLS is disabled
- GCP API key not restricted to use by specified Hosts and Apps

### Changed

#### 3 policies updated

- AWS RDS instance with copy tags to snapshots disabled 
- Azure App Service Web app doesn't have a Managed Service Identity
- Azure Network Watcher Network Security Group (NSG) flow logs are disabled

#### 2 compliance standard updated

- CIS v1.3.0 (AWS)
- CIS v1.4.0 (AWS)


## PCS-22.3.1 - 2022-03-14

### Added

#### 3 new policies

- Azure Key vault Private endpoint connection is not configured
- Azure MariaDB database server not using latest TLS version
- Azure MariaDB database server with SSL connection disabled

### Changed

#### 4 policies updated

- AWS IAM policy allows full administrative privileges
- AWS RDS Event subscription All event categories and All instances disabled for DB instance
- AWS SNS topic with cross-account access
- GCP Cloud Function HTTP trigger is not secured

#### 2 compliance standard updated

- CIS v1.3.0 (AWS)
- CIS v1.4.0 (AWS)


## PCS-22.2.1 - 2022-02-14

### Added

#### 7 new policies

- AWS EC2 instance that is internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port
- AWS EC2 instance with unrestricted outbound access to internet
- AWS RDS managed ENI reachable from any untrust internet source
- AWS Redshift managed ENI reachable from any untrust internet source
- Azure MySQL Database Server using insecure TLS version
- Azure Storage Account using insecure TLS version
- GCP VM instance OS login overrides Project metadata OS login configuration

#### 1 new auto-remediation cli

- GCP VM instance OS login overrides Project metadata OS login configuration

### Changed

#### 4 policies updated

- AWS Default Security Group does not restrict all traffic
- AWS EC2 instance with unrestricted outbound access to internet
- AWS Security Group allows all traffic on RDP port (3389)
- AWS Security Group allows all traffic on SSH port (22)

### Removed

#### 62 policies deleted

- AWS Certificate Manager (ACM) has unused certificates
- AWS CloudFormation stack configured without SNS topic
- AWS CloudFront Distributions with Field-Level Encryption not enabled
- AWS CloudWatch Log groups encrypted using default encryption key instead of KMS CMK
- AWS CloudWatch Log groups not configured with definite retention days
- AWS EBS Volume is unattached
- AWS EBS snapshot is not encrypted
- AWS EC2 instance associated with a public IP subnet
- AWS EC2 instance detailed monitoring disabled
- AWS EC2 instances with Public IP and associated with Security Groups have Internet Access
- AWS ECS fargate task definition logging is disabled
- AWS ECS/Fargate task definition execution IAM Role not found
- AWS Elastic Load Balancer (Classic) with connection draining disabled
- AWS Elastic Load Balancer v2 (ELBv2) with deletion protection feature disabled
- AWS KMS Customer Managed Key not in use
- AWS Lambda Environment Variables not encrypted at-rest using CMK
- AWS Lambda Function is not assigned to access within VPC
- AWS Lambda functions with tracing not enabled
- AWS Network ACLs allow ingress traffic to server administration ports
- AWS Network ACLs with Inbound rule to allow All ICMP IPv4
- AWS Network ACLs with Inbound rule to allow All ICMP IPv6
- AWS Network ACLs with Inbound rule to allow All Traffic
- AWS Network ACLs with Outbound rule to allow All ICMP IPv4
- AWS Network ACLs with Outbound rule to allow All ICMP IPv6
- AWS Network ACLs with Outbound rule to allow All Traffic
- AWS RDS DB snapshot is encrypted using default KMS key instead of CMK
- AWS Redshift clusters should not be publicly accessible
- AWS SNS topic encrypted using default KMS key instead of CMK
- AWS SNS topic not configured with secure data transport policy
- AWS SNS topic with server-side encryption disabled
- AWS SQS server side encryption not enabled
- AWS Security Group Inbound rule overly permissive to all traffic on all protocols (-1)
- AWS Security Group allows all traffic on CIFS port (445)
- AWS Security Group allows all traffic on DNS port (53)
- AWS Security Group allows all traffic on FTP port (21)
- AWS Security Group allows all traffic on FTP-Data port (20)
- AWS Security Group allows all traffic on ICMP (Ping) protocol
- AWS Security Group allows all traffic on MSQL port (4333)
- AWS Security Group allows all traffic on MYSQL port (3306)
- AWS Security Group allows all traffic on NetBIOS port (137)
- AWS Security Group allows all traffic on NetBIOS port (138)
- AWS Security Group allows all traffic on PostgreSQL port (5432)
- AWS Security Group allows all traffic on SMTP port (25)
- AWS Security Group allows all traffic on SQL Server port (1433)
- AWS Security Group allows all traffic on SQL Server port (1434)
- AWS Security Group allows all traffic on Telnet port (23)
- AWS Security Group allows all traffic on VNC Listener port (5500)
- AWS Security Group allows all traffic on VNC Server port (5900)
- AWS Security Group allows all traffic on Windows RPC port (135)
- AWS Security Group allows all traffic on ports which are not commonly used
- AWS Security Group overly permissive to all traffic
- [Beta] AWS EC2 instance reachable from untrust internet source on SSH/RDP port (TCP)
- Azure Virtual Machine Boot Diagnostics Disabled
- Azure Virtual Machine is not assigned to an availability set
- GCP Firewall rule logging disabled
- GCP GCE Disk snapshot not encrypted with CSEK
- GCP Pub/Sub topic is not encrypted using a customer-managed encryption key
- GCP Storage bucket encrypted using default KMS key instead of a customer-managed key
- GCP VM instances without metadata, zone or label information
- GCP compute engine image not encrypted using customer-managed key
- GCP sink not configured to export all log entries
- GCP storage bucket is not configured with default Event-Based Hold


## PCS-22.1.2 - 2022-01-31

### Added

#### 7 new policies

- AWS RDS Cluster snapshot is accessible to public
- Azure AD MFA is not enabled for the user
- Azure Key Vault Key has no expiration date (Non-RBAC Key vault)
- Azure Key Vault secret has no expiration date (Non-RBAC Key vault)
- Azure Service bus namespace configured with overly permissive authorization rules
- GCP API key not restricting any specific API
- GCP API key not rotating in every 90 days

#### 3 new compliance standard

- AWS Foundational Security Best Practices standard
- Azure Security Benchmark (V3)
- New Zealand Information Security Manual (NZISM v3.4)

### Changed

#### 6 policies updated

- AWS SQS queue access policy is overly permissive
- Azure Key Vault Key has no expiration date (RBAC Key vault)
- Azure Key Vault secret has no expiration date (RBAC Key vault)
- GCP Kubernetes Engine Clusters not configured with private cluster
- GCP VPC Flow logs for the subnet is set to off
- AWS cross-account resource access through IAM policies (IAM Security)

### Removed

#### 1 policy deleted from the IAM Security module

- AWS entities with risky permissions


## PCS-22.1.1 - 2022-01-17

### Added

#### 14 new policies

- AWS ALB attached WAFv2 WebACL is not configured with AMR for Log4j Vulnerability
- AWS API Gateway REST API not configured with AWS Web Application Firewall v2 (AWS WAFv2)
- AWS API Gateway Rest API attached WAFv2 WebACL is not configured with AMR for Log4j Vulnerability
- AWS AppSync attached WAFv2 WebACL is not configured with AMR for Log4j Vulnerability
- AWS AppSync not configured with AWS Web Application Firewall v2 (AWS WAFv2)
- AWS CloudFront attached WAFv2 WebACL is not configured with AMR for Log4j Vulnerability
- AWS CloudFront not configured with AWS Web Application Firewall v2 (AWS WAFv2)
- AWS WAF Classic (Regional) in use
- Azure Application Gateway Web application firewall (WAF) policy rule for Remote Command Execution is disabled
- Azure Front Door Web application firewall (WAF) policy rule for Remote Command Execution is disabled
- Azure Front Door does not have the Azure Web application firewall (WAF) enabled
- Azure PostgreSQL database server Infrastructure double encryption is disabled
- GCP Cloud Armor policy not configured with cve-canary rule
- OCI IAM policy with full administrative privileges across the tenancy to non Administrator

#### 33 new policies for the IAM Security module

- AWS EC2 instance with IAM permissions management access level
- AWS EC2 instance with IAM write access level
- AWS EC2 instance with org write access level
- AWS EC2 with IAM wildcard resource access
- AWS ECR Repository that is publicly accessible through IAM policies
- AWS ECS Task Definition with IAM wildcard resource access
- AWS Elasticbeanstalk Platform with IAM wildcard resource access
- AWS KMS Key that is publicly accessible through IAM policies
- AWS Lambda Function that is publicly accessible through IAM policies
- AWS Lambda Function with IAM permissions management access level
- AWS Lambda Function with IAM wildcard resource access
- AWS Lambda Function with IAM write access level
- AWS Lambda Function with org write access level
- AWS Lambda Layer Version that is publicly accessible through IAM policies
- AWS S3 bucket that is publicly accessible through IAM policies
- AWS SNS Topic that is publicly accessible through IAM policies
- AWS SQS Queue that is publicly accessible through IAM policies
- AWS Secret Manager Secret that is publicly accessible through IAM policies
- Azure AD user with effective permissions to create AWS IAM users
- ECS Task Definition with IAM permissions management access level
- ECS Task Definition with IAM write access level
- ECS Task Definition with org write access level
- Elasticbeanstalk Platform with IAM permissions management access level
- Elasticbeanstalk Platform with IAM write access level
- Elasticbeanstalk Platform with org write access level
- IAM User with IAM permissions management access level
- IAM User with IAM wildcard resource access
- IAM User with IAM write access level
- IAM User with org write access level
- Okta User with IAM permissions management access level
- Okta User with IAM wildcard resource access
- Okta User with IAM write access level
- Okta User with org write access level

#### 6 new auto-remediation cli's

- GCP Default Firewall rule is overly permissive (except http and https)
- GCP Firewall rule allows all traffic on DNS port (53)
- GCP Firewall rule allows all traffic on FTP port (21)
- GCP Firewall rule allows all traffic on RDP port (3389)
- GCP Firewall rule allows all traffic on SSH port (22)
- GCP Firewall rule allows inbound traffic from anywhere with no specific target set

#### 1 new compliance standard

- CIS v1.4.0 (Azure)

### Changed

#### 22 policies updated

- AWS CloudFront origin protocol policy does not enforce HTTPS-only
- Azure App Service Web app doesn't use latest Java version
- Azure Microsoft Defender for Cloud MCAS integration Disabled
- Azure Microsoft Defender for Cloud WDATP integration Disabled
- Azure Microsoft Defender for Cloud automatic provisioning of log Analytics agent for Azure VMs is set to Off
- Azure Microsoft Defender for Cloud email notification for subscription owner is not set
- Azure Microsoft Defender for Cloud is set to Off for App Service
- Azure Microsoft Defender for Cloud is set to Off for Azure SQL Databases
- Azure Microsoft Defender for Cloud is set to Off for Container Registries
- Azure Microsoft Defender for Cloud is set to Off for Key Vault
- Azure Microsoft Defender for Cloud is set to Off for Kubernetes
- Azure Microsoft Defender for Cloud is set to Off for SQL servers on machines
- Azure Microsoft Defender for Cloud is set to Off for Servers
- Azure Microsoft Defender for Cloud is set to Off for Storage
- Azure Microsoft Defender for Cloud security alert email notifications is not set
- Azure Microsoft Defender for Cloud security contact additional email is not set
- Azure Network Security Group allows all traffic on ports which are not commonly used
- Azure SQL database Transparent Data Encryption (TDE) encryption disabled
- GCP Firewall rule allows all traffic on DNS port (53)
- GCP Firewall rule allows all traffic on FTP port (21)
- GCP Kubernetes Engine Cluster Client Certificate is not disabled
- GCP storage bucket is not configured with default Event-Based Hold

#### 3 policies updated for the IAM Security module

- AWS cross-account resource access through IAM policies
- Azure IAM effective permissions are over-privileged (7 days)
- Azure entities with risky permissions

### Removed

#### 1 policy deleted

- AWS SNS subscription is not configured with HTTPS


## PCS-21.12.1 - 2021-12-06

### Added

#### 2 new policies

- Instance affected by Apache Log4j vulnerability is exposed to network traffic from the internet [CVE-2021-44228]
- GCP Cloud Function not enabled with VPC connector

#### 5 new Limited GA policies using the Cloud Network Analyzer Engine.

- [Beta] AWS EC2 instance reachable from untrust internet source on SSH/RDP port (TCP)
- [Beta] AWS Redshift managed ENI reachable from untrust internet source
- [Beta] AWS RDS managed ENI reachable from untrust internet source
- [Beta] AWS EC2 instance with unrestricted outbound access to internet
- [Beta] AWS EC2 instances reachable from untrust internet source other than HTTP/HTTPS port

#### 2 new auto-remediation cli's

- GCP Kubernetes cluster intra-node visibility disabled
- GCP Kubernetes Engine Clusters have binary authorization disabled

#### 5 new compliance standards

- CIS AWS 3 Tier Web Architecture Benchmark v.1.0.0
- CyberSecurity Law of the People's Republic of China
- ISO/IEC 27002:2013
- ISO/IEC 27017:2015
- ISO/IEC 27018:2019

#### 2 new frameworks

- AWS Well-Architected Framework
- MITRE ATT&CK v10.0 Cloud IaaS Matrix for Enterprise

### Changed

#### 9 policies updated

- AWS Elastic File System (EFS) not encrypted using Customer Managed Key
- AWS S3 CloudTrail bucket for which access logging is disabled
- Azure SQL database auditing is disabled
- Azure SQL Database with Auditing Retention less than 90 days
- Azure Virtual Machine Boot Diagnostics Disabled
- GCP Kubernetes Engine cluster workload identity is disabled
- GCP SQL instance configured with overly permissive authorized networks
- GCP VPC Flow logs for the subnet is set to Off
- OCI IAM local (non-federated) user account does not have a valid and current email address

#### 1 compliance standard updated

- MLPS 2.0


## PCS-21.11.1 - 2021-11-08

### Added

#### 3 new policies

- GCP Cloud Function configured with overly permissive Ingress setting
- GCP Cloud Function HTTP trigger is not secured
- GCP Cloud Run service with overly permissive ingress rule

#### 2 new compliance standards

- Azure Security Benchmark (v2)
- CIS v1.3.1 (Azure)

### Changed

#### 2 policies updated

- AWS access keys not used for more than 90 days
- AWS Amazon Machine Image (AMI) is publicly accessible


## PCS-21.10.2 - 2021-10-25

### Added

#### 1 new policy

- AWS OpenSearch Fine-grained access control is disabled

#### 4 new policies for the IAM Security module

- Azure effective permissions granting wildcard resource access
- Azure entities with risky permissions
- Azure IAM effective permissions are over-privileged (7 days)
- Azure IAM effective permissions are over-privileged (90 days)

### Changed

#### 6 policies updated

- AWS RDS instance not in private subnet
- GCP Default Firewall rule is overly permissive (except http and https)
- GCP Firewall rule allows all traffic on RDP port (3389)
- GCP Firewall rule allows all traffic on SSH port (22)
- GCP Firewall rule allows inbound traffic from anywhere with no specific target set
- GCP Projects have OS Login disabled

#### 1 policy updated for the IAM Security module

- AWS resources that are publicly accessible through IAM policies


## PCS-21.10.1 - 2021-10-11

### Added

#### 7 new policies

- AWS ECS fargate task definition logging is disabled
- AWS EMR Block public access setting disabled
- AWS EMR cluster Master Security Group allows all traffic to port 8088
- Azure Container Instance environment variable with regular value type
- Azure Container Instance is not configured with virtual network
- Azure Container Instance not configured with the managed identity
- Azure Cosmos DB allows traffic from public Azure datacenters

### Changed

#### 1 policy updated

- Memcached DDoS attack attempted


## PCS-21.9.2 - 2021-09-27

### Added

#### 1 new policy

- AWS ElastiCache Redis with in-transit encryption disabled (Non-replication group)

#### 8 new auto-remediation cli's

- Azure Function App client certificate is disabled
- Azure Function App doesn't have a Managed Service Identity
- Azure Function App doesn't redirect HTTP to HTTPS
- Azure Function App doesn't use HTTP 2.0
- Azure Function App doesn't use latest TLS version
- GCP cloud storage bucket with uniform bucket-level access disabled
- GCP Firewall rule logging disabled
- GCP Firewall with Inbound rule overly permissive to All Traffic

### Changed

#### 6 policies updated

- AWS CloudTrail is not enabled in all regions
- AWS ECR repository is exposed to public
- AWS ElastiCache Redis cluster with in-transit encryption disabled
- AWS IAM policy allows assume role permission across all services
- AWS S3 bucket accessible to unmonitored cloud accounts
- Azure Virtual Network subnet is not configured with a Network Security Group

### Removed

#### 8 policies deleted

- AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy
- AWS S3 Bucket has Global GET Permissions enabled via bucket policy
- AWS S3 Bucket has Global LIST Permissions enabled via bucket policy
- AWS S3 Bucket has Global PUT Permissions enabled via bucket policy
- Azure SQL Server advanced data security does not have an email alert recipient
- Azure SQL Server advanced data security does not send alerts to service and co-administrators
- Azure SQL server send alerts to field value is not set
- SQL DB instance backup configuration is not enabled


## PCS-21.9.1 - 2021-09-10

### Added

#### 3 new policies

- Azure Cosmos DB key based authentication is enabled
- Azure Cosmos DB Virtual network is not configured
- Azure Cosmos DB Private Endpoint Connection is not configured

### Changed

#### 2 policies updated

- AWS Network Load Balancer (NLB) is not using the latest predefined security policy
- AWS RDS database instance is publicly accessible


## PCS-21.8.2 - 2021-08-26

### Added

#### 5 new policies

- AWS ECS cluster with container insights feature disabled
- AWS RDS cluster delete protection is disabled
- AWS RDS cluster not configured with IAM authentication
- AWS RDS instance delete protection is disabled
- AWS RDS instance not configured with IAM authentication

#### 8 new auto-remediation cli's

- AWS ECS cluster with container insights feature disabled
- AWS Lambda functions with tracing not enabled
- AWS RDS cluster delete protection is disabled
- AWS RDS cluster not configured with IAM authentication
- AWS RDS instance delete protection is disabled
- AWS RDS instance not configured with IAM authentication
- Azure Storage account container storing activity logs is publicly accessible
- Azure storage account has a blob container with public access

#### 2 new compliance standard

- MAS TRM 2021
- Risk Management in Technology (RMiT)

### Changed

#### 7 policies updated

- AWS IAM role/user with unused CloudTrail delete or full permission
- AWS Lambda functions with tracing not enabled
- AWS SNS topic not configured with secure data transport policy
- Azure disk is unattached and is encrypted with the default encryption key instead of ADE/CMK
- Azure Storage account container storing activity logs is publicly accessible
- Azure storage account has a blob container with public access
- Azure VM data disk is encrypted with the default encryption key instead of ADE/CMK

#### 1 framework updated

- MITRE ATT&CK v8.2


## PCS-21.8.1 - 2021-08-12

### Added

#### 15 new policies

- AWS ECS IAM policy overly permissive to all traffic
- AWS S3 bucket policy overly permissive to any principal
- GCP MySQL instance database flag skip_show_database is not set to on
- GCP PostgreSQL instance database flag log_duration is not set to on
- GCP PostgreSQL instance database flag log_error_verbosity is not set to default or stricter
- GCP PostgreSQL instance database flag log_executor_stats is not set to off
- GCP PostgreSQL instance database flag log_hostname is not set to off
- GCP PostgreSQL instance database flag log_parser_stats is not set to off
- GCP PostgreSQL instance database flag log_planner_stats is not set to off
- GCP PostgreSQL instance database flag log_statement is not set appropriately
- GCP PostgreSQL instance database flag log_statement_stats is not set to off
- GCP SQL server instance database flag external scripts enabled is not set to off
- GCP SQL server instance database flag remote access is not set to off
- GCP SQL server instance database flag user connections is not set
- GCP SQL server instance database flag user options is set

### Changed

#### 2 policies updated

- AWS ECS/Fargate task definition execution IAM Role not found
- AWS Elastic Load Balancer (ELB) not in use

### Removed

#### 4 policies deleted

- Azure Security Center SQL auditing and threat detection monitoring is set to disabled
- Azure Security Center SQL encryption monitoring is set to disabled
- Azure Security Center storage encryption monitoring is set to disabled
- Azure Security Center vulnerability assessment monitoring is set to disabled


## PCS-21.7.2 - 2021-07-29

### Added

#### 1 new policy

- AWS EBS volume region with encryption is disabled

#### 2 new compliance standards

- CSA CCM v.4.0.1
- CIS v1.4.0 (AWS)

### Changed

#### 18 policies updated

- AWS EBS snapshot is not encrypted
- AWS EBS Snapshot with access for unmonitored cloud accounts
- AWS Elastic Load Balancer v2 (ELBv2) listener that allow connection requests over HTTP
- AWS Elastic Load Balancer v2 (ELBv2) with access log disabled
- AWS Elastic Load Balancer v2 (ELBv2) with listener TLS/SSL is not configured
- AWS Network ACLs with Inbound rule to allow All Traffic
- AWS Network ACLs with Outbound rule to allow All Traffic
- AWS RDS DB snapshot is encrypted using default KMS key instead of CMK
- AWS RDS instance is not encrypted
- AWS RDS instance with copy tags to snapshots disabled
- AWS RDS instance with Multi-Availability Zone disabled
- AWS RDS retention policy less than 7 days
- Azure SQL databases Defender setting is set to Off
- Azure Virtual Machine Boot Diagnostics Disabled
- Azure Virtual Machine is not assigned to an availability set
- Azure VM OS disk is encrypted with the default encryption key instead of ADE/CMK
- Alibaba Cloud disk automatic snapshot policy is disabled
- Alibaba Cloud ECS instance release protection is disabled

### Removed

#### 16 policy deleted

- AWS EBS volume not encrypted using Customer Managed Key
- AWS EBS volumes are not encrypted
- AWS IAM sensitive activities by User
- AWS IAM sensitive configuration updates
- Azure Virtual Machine does not have endpoint protection installed
- GCP Load balancer sensitive configuration updates
- GCP VM Instances without any Label information
- Root user activities
- Sensitive configuration updates
- Sensitive IAM updates
- Sensitive network configuration updates in AWS
- Sensitive Network configuration updates in GCP
- Sensitive permission exposed for website configuration updates of S3 Buckets
- Sensitive SQL instance updates
- Sensitive Storage configuration updates
- Sensitive User actions


## PCS-21.7.1 - 2021-07-15

### Added

#### 4 new policies

- Azure Active Directory Security Defaults is disabled
- Azure AD Users can consent to apps accessing company data on their behalf is enabled
- GCP storage bucket is logging to itself
- GCP storage bucket is not configured with default Event-Based Hold

### Changed

#### 2 policies updated

- AWS EMR cluster is not enabled with local disk encryption
- AWS EMR cluster is not enabled with local disk encryption using CMK

#### 1 compliance standard updated

- NIST CSF


## PCS-21.6.3 - 2021-07-01

### Added

#### 7 new policies

- AWS CloudWatch Log groups encrypted using default encryption key instead of KMS CMK
- AWS EC2 instance detailed monitoring disabled
- AWS ECS Cluster instance volume encryption for data at rest is disabled
- AWS Elasticsearch domain is not configured with HTTPS
- AWS IAM policy allows decryption actions on all KMS keys
- AWS VPC endpoint policy is overly permissive
- GCP App Engine Identity-Aware Proxy is disabled

### Changed

#### 6 policies updated

- AWS Elasticsearch domain has Dedicated master set to disabled
- AWS Elasticsearch domain Encryption for data at rest is disabled
- AWS Elasticsearch domain has Index slow logs set to disabled
- AWS Elasticsearch domain has Search slow logs set to disabled
- AWS Elasticsearch domain has Zone Awareness set to disabled
- AWS Elasticsearch domain publicly accessible

### Removed

#### 1 policy deleted

- AWS ElasticSearch cluster not in a VPC


## PCS-21.6.2 - 2021-06-17

### Added

#### 4 new policies

- AWS CloudWatch Log groups not configured with definite retention days
- AWS ElastiCache Redis cluster encryption not configured with CMK key
- AWS IAM policy is overly permissive to all traffic via condition clause
- AWS IAM policy overly permissive to STS services

#### 1 new compliance standard

- HITRUST v.9.4.2

### Changed

#### 11 policies updated

- AWS EC2 instance allowing public IP in subnets
- AWS ECS task definition elevated privileges enabled
- AWS ECS/ Fargate task definition execution IAM Role not found
- AWS Security Group allows all traffic on ports which are not commonly used
- Azure Key Vault audit logging is disabled
- Azure Security Center 'Standard pricing tier' is not selected
- Azure SQL Server advanced data security is disabled
- Azure Virtual Network subnet is not configured with a Network Security Group
- GCP User managed service account keys are not rotated for 90 days
- Storage Bucket does not have Access and Storage Logging enabled
- Threat Detection on SQL databases is set to Off


## PCS-21.6.1 - 2021-06-03

### Added

#### 3 new policies

- AWS IAM configuration updates invoked from Parrot Security Linux machine
- AWS IAM configuration updates invoked from Pentoo Linux machine
- AWS IAM configuration updates invoked from Kali Linux machine

#### 1 new compliance standard

- CIS v1.2.0 (GCP)

### Changed

#### 3 policies updated

- AWS Lambda Function is not assigned to access within VPC
- AWS Elastic Load Balancer (Classic) with access log disabled
- AWS Lambda Environment Variables not encrypted at-rest using CMK


## PCS-21.5.2 - 2021-05-20

### Added

#### 8 new policies

- AWS Elastic IP not in use
- AWS SNS topic not configured with secure data transport policy
- AWS SNS topic with cross-account access
- Azure Activity log alert for delete policy assignment does not exist
- Azure Monitor Diagnostic Setting does not captures appropriate categories
- Azure Storage account containing VHD OS disk is not encrypted with CMK
- OCI users Auth Tokens have aged more than 90 days without being rotated
- OCI users customer secret keys have aged more than 90 days without being rotated

#### 1 new auto-remediation cli

- GCP VM instances have block project-wide SSH keys feature disabled 

### Changed

#### 18 policies updated

- AWS CloudFormation stack configured without SNS topic
- AWS Customer Master Key (CMK) rotation is not enabled
- AWS IAM Groups with administrator access permissions
- AWS SQS server side encryption not enabled
- GCP SQL database instance is not configured with automated backups
- GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)
- GCP VM instance configured with default service account
- GCP VM instance using a default service account with full access to all Cloud APIs
- GCP VM instance with Shielded VM features disabled
- GCP VM instance with the external IP address
- GCP VM Instances enabled with Pre-Emptible termination
- GCP VM instances have block project-wide SSH keys feature disabled
- GCP VM instances have IP Forwarding enabled
- GCP VM instances have serial port access enabled
- GCP VM instances with excessive service account permissions
- GCP VM Instances without any Custom metadata information
- GCP VM Instances without any Label information
- GCP VM instances without metadata, zone or label information


## PCS-21.5.1 - 2021-05-05

### Added

#### 6 new policies

- AWS Amazon Machine Image (AMI) infected with mining malware
- AWS ECS cluster not configured with a registered instance
- AWS ECS cluster not configured with active services
- AWS SNS topic is exposed to unauthorized access
- Azure Security Center Defender set to Off for Container Registries
- Azure Security Center Defender set to Off for SQL servers on machines

### Changed

#### 4 policies updated

- AWS IAM policy allows assume role permission across all services
- Azure Load Balancer diagnostics logs are disabled
- GCP Firewall rules allow inbound traffic from anywhere with no target tags set
- GCP Projects have OS Login disabled


## PCS-21.4.2 - 2021-04-20

### Added

#### 6 new policies

- AWS Application Load Balancer (ALB) not configured with AWS Web Application Firewall v2 (AWS WAFv2)
- AWS EC2 instance not configured with Instance Metadata Service v2 (IMDSv2)
- AWS Security Group allows all traffic on ICMP (Ping) protocol
- Azure Network Security Group allows all traffic on ports which are not commonly used
- GCP Pub/Sub topic is not encrypted using a customer-managed encryption key
- GCP VM instance template with IP forwarding enabled

#### 2 new compliance standards

- NIST SP 800-172
- MPAA Content Protection Best Practices (Motion Picture Association of America Version 4.08)

### Changed

#### 4 policies updated

- AWS Elastic Load Balancer (ELB) with ACM certificate expiring in 90 days
- AWS Redshift Cluster not encrypted using Customer Managed Key
- AWS Redshift instances are not encrypted
- Azure Security Center 'Standard pricing tier' is not selected


## PCS-21.4.1 - 2021-04-09

### Added

#### 4 new policies

- AWS SNS topic policy overly permissive for publishing
- AWS SNS topic policy overly permissive for subscription
- Azure Key Vault Firewall is not enabled
- Azure Key Vault Purge protection is not enabled

#### 1 new compliance standard

- NIST SP 800-171 Revision 2

#### 7 policies for the new IAM Security module

- AWS IAM effective permissions are over-privileged (7 days)
- AWS IAM effective permissions are over-privileged (90 days)
- AWS cross-account resource access through IAM policies
- AWS effective permissions granting wildcard resource access
- AWS entities with risky permissions
- AWS resources that are publicly accessible through IAM policies
- Okta user with effective permissions to create AWS IAM users

### Changed

#### 11 policies updated

- AWS IAM policy allows assume role permission across all services
- Azure Application Gateway does not have the Web application firewall (WAF) enabled
- GCP Log metric filter and alert does not exist for Audit Configuration Changes
- GCP Log metric filter and alert does not exist for Cloud Storage IAM permission changes
- GCP Log metric filter and alert does not exist for IAM custom role changes
- GCP Log metric filter and alert does not exist for Project Ownership assignments/changes
- GCP Log metric filter and alert does not exist for SQL instance configuration changes
- GCP Log metric filter and alert does not exist for VPC Network Firewall rule changes
- GCP Log metric filter and alert does not exist for VPC network changes
- GCP Log metric filter and alert does not exist for VPC network route changes
- Threat Detection on SQL databases is set to Off

#### 1 compliance standard updated

- PCI DSS v3.2.1

### Removed

#### 1 policy deleted

- Azure Security Center web application firewall monitoring is set to disabled


## PCS-21.3.2 - 2021-03-25

### Added

#### 3 new policies

- GCP Firewall rule logging disabled
- GCP Log bucket retention policy not enabled
- GCP Log bucket retention policy is not configured using bucket lock

#### 1 new framework

- MITRE ATT&CK v8.2 Cloud Matrix for Enterprise

#### 2 new compliance standards

- Brazilian Data Protection Law (LGPD) 
- CIS Alibaba Cloud Foundation Benchmark v.1.0.0 

### Changed

#### 7 policies updated

- AWS Elastic Load Balancer v2 (ELBv2) listener that allow connection requests over HTTP
- AWS Network ACLs allow ingress traffic to server administration ports
- DB ports exposed to network traffic from the internet
- Instance is communicating with ports known to mine Bitcoin
- Instance is communicating with ports known to mine Ethereum
- Instances exposed to network traffic from the internet
- OCI File Storage File System Export is publicly accessible

#### 1 compliance standard updated

- CIS Azure v1.3.0

### Removed

#### 1 policy deleted

- AWS KMS sensitive configuration updates


## PCS-21.3.1 - 2021-03-10

### Added

#### 7 new policies

- Azure Container registries Public access to All networks is enabled
- Azure Function App authentication is off
- Azure Function App client certificate is disabled
- Azure Function App doesn't have a Managed Service Identity
- Azure Function App doesn't redirect HTTP to HTTPS
- Azure Function App doesn't use HTTP 2.0
- Azure Function App doesn't use latest TLS version

#### 2 new compliance standards

- Cybersecurity Maturity Model Certification (CMMC) v.1.02
- CIS v1.3.0 (Azure)

### Changed

#### 13 policies updated

- AWS Default Security Group does not restrict all traffic
- AWS RDS database not encrypted using Customer Managed Key

- Azure App Service Web app authentication is off
- Azure App Service Web app client certificate is disabled
- Azure App Service Web app doesn't have a Managed Service Identity
- Azure App Service Web app doesn't redirect HTTP to HTTPS
- Azure App Service Web app doesn't use HTTP 2.0
- Azure App Service Web app doesn't use latest TLS version
- Azure Load Balancer diagnostics logs are disabled
- Azure SQL Server advanced data security does not send alerts to service and co-administrators

- GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)
- GCP VM instances have IP Forwarding enabled
- GCP VM instances with excessive service account permissions

#### 3 compliance standards updated

- CIS v1.3.0 (AWS)
- CIS v1.1.0 (GCP)
- CIS v1.1.0 (GKE)

### Removed

#### 2 policies deleted

- GCP API key not restricting any specific API
- GCP API key not rotating in every 90 days


## PCS-21.2.2 - 2021-02-25

### Added

#### 45 new policies

- AWS S3 configuration updates invoked from Kali Linux machine
- AWS S3 configuration updates invoked from Parrot Security Linux machine
- AWS S3 configuration updates invoked from Pentoo Linux machine

- Azure CDN Endpoint Custom domains is not configured with HTTPS
- Azure CDN Endpoint Custom domains using insecure TLS version

- OCI Block Storage Block Volume does not have backup enabled
- OCI Block Storage Block Volume is not restorable
- OCI Block Storage Block Volumes are not encrypted with a Customer Managed Key (CMK)
- OCI Compute Instance boot volume has in-transit data encryption is disabled
- OCI Compute Instance has Legacy MetaData service endpoint enabled
- OCI Compute Instance has monitoring disabled
- OCI Default Security List of every VCN allows all traffic on SSH port (22)
- OCI Event Rule and Notification does not exist for IAM group changes
- OCI Event Rule and Notification does not exist for IAM policy changes
- OCI Event Rule and Notification does not exist for Identity Provider changes
- OCI Event Rule and Notification does not exist for Identity Provider Group (IdP) group mapping changes
- OCI Event Rule and Notification does not exist for network gateways changes
- OCI Event Rule and Notification does not exist for Network Security Groups changes
- OCI Event Rule and Notification does not exist for route tables changes
- OCI Event Rule and Notification does not exist for security list changes
- OCI Event Rule and Notification does not exist for user changes
- OCI Event Rule and Notification does not exist for VCN changes
- OCI File Storage File System access is not restricted to root users
- OCI File Storage File System Export is publicly accessible
- OCI File Storage File Systems are not encrypted with a Customer Managed Key (CMK)
- OCI IAM local (non-federated) user account does not have a valid and current email address
- OCI IAM password policy for local (non-federated) users does not have a lowercase character
- OCI IAM password policy for local (non-federated) users does not have a number
- OCI IAM password policy for local (non-federated) users does not have a symbol
- OCI IAM password policy for local (non-federated) users does not have an uppercase character
- OCI IAM password policy for local (non-federated) users does not have minimum 14 characters
- OCI MFA is disabled for IAM users
- OCI Network Security Group allows all traffic on RDP port (3389)
- OCI Network Security Groups (NSG) has stateful security rules
- OCI Object Storage bucket does not emit object events
- OCI Object Storage Bucket has object Versioning disabled
- OCI Object Storage Bucket is not encrypted with a Customer Managed Key (CMK)
- OCI Object Storage bucket is publicly accessible
- OCI security group allows unrestricted ingress access to port 22
- OCI Security List allows all traffic on SSH port (22)
- OCI security lists allows unrestricted ingress access to port 3389
- OCI tenancy administrator users are associated with API keys
- OCI users API keys have aged more than 90 days without being rotated
- OCI VCN has no inbound security list
- OCI VCN Security list has stateful security rules

#### 2 new compliance standards

 - CIS v1.0.0 (OCI)
 - CIS v1.1.0 (OCI)

### Changed

#### 5 policies updated

- AWS S3 buckets are accessible to public
- AWS VPC has flow logs disabled
- GCP Storage buckets are publicly accessible to all authenticated users
- GCP Storage buckets are publicly accessible to all users
- GCP VM instances have block project-wide SSH keys feature disabled


## PCS-21.2.1 - 2021-02-11

### Added

#### 18 new policies

- AWS Classic Load Balancer is in use for internet-facing applications
- AWS KMS Key policy overly permissive
- AWS KMS sensitive configuration updates
- AWS S3 bucket publicly readable
- AWS S3 bucket publicly writable
- AWS SageMaker notebook instance with root access enabled
- Azure Security Center MCAS integration Disabled
- Azure Security Center WDATP integration Disabled
- Azure SQL Server ADS Vulnerability Assessment 'Also send email notifications to admins and subscription owners' is disabled
- Azure SQL Server ADS Vulnerability Assessment 'Send scan reports to' is not configured
- Azure SQL Server ADS Vulnerability Assessment is disabled
- Azure SQL Server ADS Vulnerability Assessment Periodic recurring scans is disabled
- Azure Storage accounts soft delete is disabled
- GCP API key not restricting any specific API
- GCP API key not rotating in every 90 days
- GCP compute engine image not encrypted using customer-managed key
- GCP GCE Disk snapshot not encrypted with CSEK
- GCP KMS encryption key not rotating in every 90 days

### Changed

#### 15 policies updated

- AWS IAM policy allows assume role permission across all services
- GCP Firewall rule allows internet traffic to DNS port (53)
- GCP Firewall rule allows internet traffic to FTP port (21)
- GCP Firewall rule allows internet traffic to HTTP port (80)
- GCP Firewall rule allows internet traffic to Microsoft-DS port (445)
- GCP Firewall rule allows internet traffic to MongoDB port (27017)
- GCP Firewall rule allows internet traffic to MySQL DB port (3306)
- GCP Firewall rule allows internet traffic to NetBIOS-SSN port (139)
- GCP Firewall rule allows internet traffic to Oracle DB port (1521)
- GCP Firewall rule allows internet traffic to POP3 port (110)
- GCP Firewall rule allows internet traffic to PostgreSQL port (5432)
- GCP Firewall rule allows internet traffic to RDP port (3389)'
- GCP Firewall rule allows internet traffic to SMTP port (25)
- GCP Firewall rule allows internet traffic to SSH port (22)
- GCP Firewall rule allows internet traffic to Telnet port (23)


## PCS-21.1.2 - 2021-01-28

### Added

#### 21 new policies

- AWS Application Load Balancer (ALB) is not using the latest predefined security policy
- AWS Database Migration Service (DMS) has expired certificates
- AWS EBS snapshot is not encrypted
- AWS Elastic Load Balancer v2 (ELBv2) load balancer with invalid security groups
- AWS Glue connection do not have SSL configured
- AWS Network Load Balancer (NLB) is not using the latest predefined security policy
- AWS SQS queue access policy is overly permissive
- Azure PostgreSQL Database Server Firewall rule allow access to all IPV4 address
- Azure Security Center Defender set to Off for App Service
- Azure Security Center Defender set to Off for Azure SQL database servers
- Azure Security Center Defender set to Off for Key Vault
- Azure Security Center Defender set to Off for Kubernetes
- Azure Security Center Defender set to Off for Servers
- Azure Security Center Defender set to Off for Storage
- Azure SQL Servers Firewall rule allow access to all IPV4 address
- Azure Virtual machine NIC has IP forwarding enabled
- GCP GCR Container Vulnerability Scanning is disabled
- GCP Kubernetes cluster shielded GKE node with integrity monitoring disabled
- GCP Kubernetes cluster shielded GKE node with Secure Boot disabled
- GCP Kubernetes Engine cluster not using Release Channel for version management
- GCP Kubernetes Engine cluster workload identity is disabled

#### 1 new compliance standard

 - Australian Prudential Regulation Authority (APRA) Prudential Standard (CPS 234)

### Changed

#### 6 policies updated

- AWS Application Load Balancer (ALB) listener that allow connection requests over HTTP
- AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled
- AWS IAM policy allows full administrative privileges
- Internet exposed instances
- Primitive IAM roles should not be used
- Publicly exposed DB Ports


## PCS-21.1.1 - 2021-01-14

### Added

#### 11 new policies

 - AWS Elastic Load Balancer v2 (ELBv2) SSL negotiation policy configured with weak ciphers
 - AWS Elastic Load Balancer v2 (ELBv2) with deletion protection feature disabled
 - AWS IAM role/user with unused CloudTrail delete or full permission
 - AWS S3 bucket having policy overly permissive to VPC endpoints
 - Azure App Services FTP deployment is All allowed
 - Azure Custom Role Administering Resource Locks not assigned
 - Azure Key vaults diagnostics logs are disabled
 - Azure PostgreSQL Database Server 'Allow access to Azure services' enabled
 - Azure Storage account Encryption Customer Managed Keys Disabled
 - Azure Virtual Machines are not utilising Managed Disks
 - Azure Virtual machine scale sets are not utilising Managed Disks

#### 1 new compliance standard

 - CIS v1.2.0 (Azure)

### Changed

#### 6 policies updated

 - AWS Default Security Group does not restrict all traffic
 - AWS EKS cluster security group overly permissive to all traffic
 - AWS Security Group Inbound rule overly permissive to all traffic on all protocols (-1)
 - AWS Security Group allows all traffic on ports which are not commonly used
 - AWS Security Group overly permissive to all traffic
 - Internet connectivity via TCP over insecure port


## PCS-20.12.2 - 2020-12-17

### Added

#### 3 new policies

- Azure Virtual Machine Boot Diagnostics Disabled
- Azure Virtual Machine scale sets Boot Diagnostics Disabled
- Azure App Services Remote debugging is enabled

### Changed

#### 5 policies updated

- AWS Elastic File System (EFS) with encryption for data at rest is disabled
- Azure storage account logging for tables is disabled
- Azure storage account logging for queues is disabled
- Alibaba Cloud MFA is disabled for RAM user
- Alibaba Cloud Security group is overly permissive


## PCS-20.12.1 - 2020-12-03

### Changed

#### 22 policies updated

- AWS Security Groups allow internet traffic to SSH port (22)
- AWS Security Groups allow internet traffic from internet to Windows RPC port (135)
- AWS Security Groups allow internet traffic from internet to NetBIOS port (138)
- AWS Security Groups allow internet traffic from internet to MSQL port (4333)
- AWS Security Groups allow internet traffic from internet to RDP port (3389)
- AWS Security Groups allow internet traffic from internet to Telnet port (23)
- AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)
- AWS Security Groups allow internet traffic from internet to SQLServer port (1434)
- AWS Security Groups allow internet traffic from internet to MYSQL port (3306)
- AWS Security Groups allow internet traffic from internet to SMTP port (25)
- AWS Security Groups allow internet traffic from internet to DNS port (53)
- AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)
- AWS Security Groups allow internet traffic from internet to FTP- Data port (20)
- AWS Security Groups allow internet traffic from internet to CIFS port (445)
- AWS Security Groups allow internet traffic from internet to FTP port (21)
- AWS Security Groups allow internet traffic from internet to SQLServer port (1433)
- AWS Security Groups allow internet traffic from internet to NetBIOS port (137)
- AWS Security Groups allow internet traffic from internet to VNC Server port (5900)
- Azure Network Security Group having Inbound rule overly permissive to all traffic on UDP protocol
- Azure Network Security Group having Inbound rule overly permissive to all traffic on any protocol
- Azure Network Security Group having Inbound rule overly permissive to all traffic on TCP protocol
- GCP Kubernetes Engine Clusters have HTTP load balancing disabled

#### 2 additional policies mapped to CIS v1.1 (Azure)

- Azure Network Security Group having Inbound rule overly permissive to all traffic on UDP protocol
- Azure Network Security Group having Inbound rule overly permissive to all traffic on any protocol


## PCS-20.11.2 - 2020-11-19

### Added

- Initial commit of all 548 policies in this repository
