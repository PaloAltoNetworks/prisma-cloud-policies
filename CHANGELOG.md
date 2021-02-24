# Changelog

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

#### 1 new framework

- MITRE ATT&CK v8

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
