# Changelog

## PCS-20.1.2 - 2021-01-28

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

### Changed

#### 6 policies updated

- AWS Application Load Balancer (ALB) listener that allow connection requests over HTTP
- AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled
- AWS IAM policy allows full administrative privileges
- Internet exposed instances
- Primitive IAM roles should not be used
- Publicly exposed DB Ports


## PCS-20.1.1 - 2021-01-14

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
