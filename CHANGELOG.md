# Changelog

## [PCS-20.12.1]

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


## [PCS-20.11.2]

### Added

- Initial commit of all 548 policies in this repository
