# Changelog

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
