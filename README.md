# Comp3010
## Table of Contents
- [Introduction](#introduction)
- [SOC Roles & Incident Handling](#soc-roles--incident-handling)
  - [Tier 1 (Triage and Monitoring)](#tier-1-triage-and-monitoring)
  - [Tier 2 (Incident Investigation)](#tier-2-incident-investigation)
  - [Tier 3 (Threat Hunting and Specialist Expertise)](#tier-3-threat-hunting-and-specialist-expertise)
- [Incident Handling Method](#incident-handling-method)
  - [Prevention](#prevention)
  - [Detection](#detection)
  - [Response](#response)
  - [Recovery](#recovery)
- [Incident Handling Reflection](#incident-handling-reflection)
- [Installation and Data Preparation](#installation-and-data-preparation)
- [Guided Questions](#guided-questions)
  - [Question 1](#question-1)
  - [Question 2](#question-2)
  - [Question 3](#question-3)
  - [Question 4](#question-4)
  - [Question 5](#question-5)
  - [Question 6](#question-6)
  - [Question 7](#question-7)
  - [Question 8](#question-8)
- [Conclusion](#conclusion)
- [References](#references)


# Introduction
This report investigates Boss of the SOC v3 (BOTSv3) dataset, which is a publicly available Splunk Capture the Flag scenario which simulates a cyber-attack against the fictional brewing company Frothy. The CTF is designed for security operational professionals to practice their incident detection and network forensics skills. Security operations Centre (SOC) is where analysts are typically housed.
# SOC Roles & Incident Handling
The BOTSv3 exercise has provided a realstic example to demonstrate how Security Operations Centre (SOC) roles and incident handling methodologies work hand in hand during a cyber incident investgiation. Typically SOC analysts are divideed into tiers based on experience and responsibilities. (REFERENCE)
## SOC Tiers and Responsibilities
### Tier 1 (Triage and Monitoring)

### Tier 2 (Incident Investigation)

### Tier 3 (Threat Hunting and Specialist Expertise)

## Incident Handling Method

## Splunk Installiation and Data Prepration
### Installing Splunk
I created an account with Splunk Enterprise, naviageted to the Linux download and copied the .tgz wget link. I opened up my Ubuntu Virtuall Machine, opened terminal then navigated to Desktop where I pasted the link into the termanl and ran it.
![alt text](<Screenshot 2025-12-19 113734v.png>)
I then installed splunk using the command: sudo tar xvzf splunk-10.0.1-c486717c32b-linux-amd64.tgz -C /opt/
To run splunk I cd-ed into /opt/splunk/bin directory and used the command ./splunk start --accept-license
After signing in using an administair account, this locally hosts splunk on my virtual machine.
You then need to make an admin account for splunk, and sign in when prompted when follwing the link to the locally  hosted application. 
### Adding the License
To add the lincense I naviagted to the license file stored on the dle, using the borwser inside my VM. I saved the file to my downloads. Then when inside splunk, If you go into settings and then licensing, you can upload the license to your account.
### Installing the dataset
Navigate to the Boss of the SOC (BOTS) Dataset Version 3 gitHub page on the VM. Download the dataset following the link. Extract the file when inside the VM.
In command prompt type sudo su to become root.
Cd into downloads to find the dataset.
Type in the command cp -r botsv3_data_set /opt/splunk/etc/apps
CD into /opt/splunk/etc/apps
When you type ls you can see the dataset is in there
![alt text](image-38.png)
![alt text](image-41.png)
![alt text](image-42.png)
![alt text](image-43.png)
![alt text](image-44.png)
![alt text](image-45.png)
### Validate its working

--
![alt text](image.png)
![alt text](image-1.png)
![alt text](image-2.png)
![alt text](image-30.png)
![alt text](image-31.png)
![alt text](image-32.png)
![alt text](image-33.png)
![alt text](image-34.png)
![alt text](image-35.png)
![alt text](image-36.png)
![alt text](image-37.png)
![alt text](<Screenshot 2025-12-19 111920.png>)
![alt text](<Screenshot 2025-12-19 113817.png>)
![alt text](<Screenshot 2025-12-19 113846.png>) 
![alt text](<Screenshot 2025-12-19 113952.png>) 
![alt text](<Screenshot 2025-12-19 114034.png>) 
![alt text](<Screenshot 2025-12-19 114124.png>) 
![alt text](<Screenshot 2025-12-19 114142.png>) 
![alt text](<Screenshot 2025-12-19 114303.png>) 
![alt text](<Screenshot 2025-12-19 114320.png>) 
![alt text](<Screenshot 2025-12-19 114339.png>) 
![alt text](<Screenshot 2025-12-19 114406.png>) 
![alt text](<Screenshot 2025-12-19 114424.png>) 
![alt text](<Screenshot 2025-12-19 112310.png>) 
![alt text](<Screenshot 2025-12-19 112421.png>)
![alt text](<Screenshot 2025-12-19 112500.png>) 
![alt text](<Screenshot 2025-12-19 112532.png>)
![alt text](<Screenshot 2025-12-19 112647.png>) 
![alt text](<Screenshot 2025-12-19 112702.png>) 
![alt text](<Screenshot 2025-12-19 113141.png>) 
![alt text](<Screenshot 2025-12-19 113201.png>) 
![alt text](<Screenshot 2025-12-19 113734 ...png>)
![alt text](<Screenshot 2025-12-19 113734v.png>)
![alt text](image-39.png)
![alt text](image-40.png)



## Key Indicators of Compromise
Theres a few key areas which indicate the system has been compromised.
- A cloud administrator account had unexpected use, especially for sensitive and critical actions such as creating users or changing permission levels
- This cloud access occured without multifactor authentication, increasing the likelihood that this was actually a leaked crediential
- Cloud storage was publically exposed when internal or configuration file are uploaded
- Unusual activitiy and unauthorised changes to cloud infrastructure, like new servers appearing unexpectedly
- Unknown and untrusted sources managed to succesfully upload into the cloud storage
- Systems were running different operating systems or configurations compared to the standard environment
- Activity that suggests reconnaissance, like searching for internal, financial or confidential data
- Actions indicating data exposure or loss, inclding public access settings or suspicious file transfer

## Recovery time line

### Prevention
### Detection
### Response
### Recovery
## Timeline of Events for Enitire Scenario
Below is the timeline of events for the incident that occured on the 20th of August 2018 indentified through the use of Splunk

09:16:12 The IAM user AKIAJOGCDXJ5NW5PXUPA/web_admin begins attempting to access IAM resources.

09:16:12 The same user attempts to create a user named nullweb_admin Xenial Xerus instance.

09:16:12 An email alert reports that the credentials for AKIAJOGCDXJ5NW5PXUPA/web_admin were discovered on GitHub.

09:27:06 The user attempts to describe the AWS account.

09:27:07 IAM access attempts by AKIAJOGCDXJ5NW5PXUPA/web_admin conclude.

An attacker gained access to a cloud administrator account after its credentials were accidentally exposed on GitHub. They briefly explored the cloud environment, attempted to create a new user for persistent access, and tried to launch a virtual server before the activity was detected and access was terminated.

09:55:14 A malicious email attachment titled Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm is received.

09:55:52 Sysmon detects execution of HxTsr.exe, originating from the malicious attachment.

09:56:39 Symantec also detects HxTsr.exe as malicious.

09:57:17 Image files (stout.png, stout-2.png, morebeer.jpg) are uploaded to OneDrive.

09:57:33 A shortcut file named BRUCE BIRTHDAY HAPPY HOUR PICS.lnk is uploaded to OneDrive.

09:59:04 The shortcut file is executed for the first time.

A staff member received a convincing email with what appeared to be a legitimate financial spreadsheet, but the attachment was malicious. When it was opened, harmful software was quietly installed on the computer, which security tools later detected. The attacker then hid their access by uploading harmless-looking files and a shortcut to the user’s OneDrive, allowing the malware to be re-activated later without relying on the original email.

10:01:44 The compromised host establishes its first connection to a command-and-control (C2) server.

10:07:07 Additional communication with the C2 server is observed.

10:08:17 A new Windows account named svcvnc is created.

10:08:17 The svcvnc account is added to the Administrators group.

10:08:35 The svcvnc account is also added to the Users group.

10:11:02 Further C2 communication takes place.

10:15:28 Another C2 server connection is recorded.

Once the computer was infected, it began communicating with an external server controlled by the attacker, allowing them to issue commands remotely. The attacker then created a new user account on the system and gave it full administrative access, ensuring continued control even if the original compromise was discovered. Regular communication with the external server continued, confirming the attacker maintained active control of the system.

10:43:10 The malware hdoor.exe performs network scanning activity.

10:47:16 A file named logos.png, containing attack tools, is downloaded from 45.77.53.176:3333.

10:48:28 Searches are conducted for the keywords “cromdale OR beer OR financial OR secret”.

The attacker began scanning the internal network to identify other systems and valuable information, downloaded additional attack tools disguised as an image file, and searched for sensitive business and financial data within the environment.

11:05:4 The first instance of remote code execution occurs using iexplorer.exe, exploiting CVE-2017-9791.
11:08:36 A file named colonel is streamed using iexplorer.exe.

11:08:48 The file definitelydontinvestigatethisfile.sh is streamed via the same process.

11:21:40 A BCC email forwarding rule is added, redirecting mail to hyunki1984@naver.com

The attacker exploited a known software weakness to remotely run their own commands on the system and transfer additional files to it. They then set up a hidden email forwarding rule so that copies of company emails were secretly sent to an external address, allowing ongoing monitoring and potential data theft without the user’s knowledge.

11:24:28 The Kevin Lagerfield Azure AD account is activated.

11:24:54 A Linux account named tomcat7 is created.

11:28:30 The shortcut file BRUCE BIRTHDAY HAPPY HOUR PICS.lnk is executed for the final time.

11:31:54 Netcat begins listening on port 1337.

11:32:14 Another connection to the C2 server is established.

11:34:01 The final remote code execution using iexplorer.exe (CVE-2017-9791) occurs.

11:34:49 The tomcat8 account executes ./colonelnew, achieving root privilege escalation via CVE-2017-16995.

The attacker activated additional user accounts across cloud and server systems, likely to expand and preserve access. They reused the earlier malicious shortcut to re-trigger the infection, opened a hidden backdoor that allowed direct remote access, and continued communicating with their external control server. Finally, they exploited another system weakness to gain full control of a server, giving them unrestricted access to data and system functions.

11:41:36 The password for the Kevin Lagerfield Azure AD account is reset.

11:42:51 A second password reset is performed on the same account.

11:43:22 The account password is changed.

11:48:38 The root user deletes /usr/share/tomcat8/.bash_history to remove evidence.

11:55:34 Netcat stops listening on port 1337.

The attacker took control of a user account by repeatedly resetting and changing its password, locking out the legitimate user. They then deleted system history records to hide evidence of their actions and closed the temporary remote access channel, indicating an attempt to cover their tracks after completing their activity.

13:01:46 The frothlywebcode S3 bucket is configured to be publicly accessible.

13:02:44 A file named OPEN_BUCKET_PLEASE_FIX.txt is uploaded to the bucket.

13:04:17 The archive frothly_html_memcached.tar.gz is uploaded to the same bucket.

The attacker changed the settings on a company cloud storage location to make it publicly accessible, exposing its contents to anyone on the internet. They then uploaded files to the storage area, including an archive likely containing internal data, increasing the risk of data exposure or unauthorised access.

13:33:24 EC2 instance gacrux.i-0cc93bade2b3cba63 is auto-scaled.

13:37:33 A Coinhive DNS lookup is detected on BSTOLL-L.

13:37:40 The first detection of BTUN-L JSCoinMiner occurs.

13:37:50 Chrome-based Monero mining begins on BSTOLL-L.

13:46:47 The final detection of BTUN-L JSCoinMiner is logged.

13:57:54 The frothlywebcode S3 bucket is returned to private access.

14:05:23 Monero mining activity on BSTOLL-L ends.

The attacker triggered the automatic creation of additional cloud servers and then used a compromised company computer to secretly run cryptocurrency-mining software for personal gain. This misuse consumed company computing resources and could have increased costs and reduced system performance. Access to the exposed cloud storage was later restricted again, and the unauthorised mining activity eventually stopped.

14:23:19 EC2 instance gacrux.i-06fea586f3d3c8ce8 is auto-scaled.

14:25:21 EC2 instance gacrux.i-09cbc261e84259b54 is auto-scaled.

14:47:12 Azure AD account bgist@froth.ly is disabled by fyodor@froth.ly

Additional cloud servers were automatically created, likely as a result of the earlier compromise, increasing resource usage and potential costs. Later in the day, a company administrator disabled a user account, indicating that remediation actions had begun to contain and limit the incident.

15:07:22 A brute-force attack against web servers originating from 5.101.40.81 begins.

15:08:12 The brute-force activity ends.

15:11:35 A Memcached attack starts.

15:27:09 The Memcached attack concludes.

15:15:00 An email is sent boasting about the successful exfiltration of customer data.

Toward the end of the incident, attackers attempted automated login attacks against company web servers and then launched another attack aimed at extracting stored data. An email was later sent claiming that customer data had been successfully stolen, indicating a high risk of data exposure and potential reputational and regulatory impact.
# Incident Response 
Thia incident relates to unaothrzed exposure risk within Frothlys AWS environment, which was identified through log-based analysis using AWS CloudTrail, S3 access logs, hardware telemetry and Windows host monitoring data.

This investigation releaved identity usage patterns, misconfigured access controls and potentail data exposure caused by a publicily accessible S3 bucket.

The incident manily affected; confidentiallity of the data stored in an S3, idenitity assurance due to API activity with MFA and operational trust in cloud goverance controls.

### Detection
The incident was discovered through systematic log anlysis using Splunk by querying AWS_native telemtry sources. Evidence supporting the dsicovering is documeneted in the README including:
- Search queries used
- Source types selected
- Fields extracted
- EVent IDs and timestamps

This demonstates repeatabke, audiatble detection, aligning with idustry SOC investigation practices. 

### Identity and Access Analysis 
Analysis of CloudTrail logs revealed that bstoll, btun, splunk_access,web_admin accessed AWS services either successfully or unsuccessfully.

#### Operations Impact
Identifying IAM users invloved is crital as it defines accountability for actions performed, it suppoers least-privilege validation and allows target credential rotation or suspension.

AWS confrims that CloudTrail records every API call made by or n behalf of an IAM identity, including failed attempts, making it the authoritative source for IAM activity verification. SOURCE
https://docs.aws.amazon.com/pdfs/awscloudtrail/latest/userguide/awscloudtrail-ug.pdf

### MFA Control Failure Detection
The investigation identified the CloudTrail field used to detect AWS API activity without multi-factor authenication.

#### Security Significance
API calls made without MFA can significatly increase the risk of credential compromise, the blast radius of stolen access keys and the likilhood of auotmated abuse. 

AWS explicility recommends montiring this field and triggering alerts when MFA is absent, particaully for sensitive services such as S3, IAM and EC2. SOURCE
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Security.html
https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-tutorials.html

### Infrastructure Conext, Processor Identification
Hardware telemetry analysis revealed the web servers were running on the E5-2676 processor. This processir architecture supports accurate incident scoping, performace analysis during abuse and validation of homogenous infrastructure assumptions.This ensure alerts and baselines are not falsely attributed to hardware discrepancies.

### Route Cause, Public S3 Bucket Misconfiguration
An S3 bucket, frothlywebcode, was made publicily accessible by bstoll due to an API call ab45689d-69cd-41e7-8705-5350402cf7ac

AWS explicitly states that incorrect ACLs are a leading cuase of sata exposure incidents and PutBucketAcl is the API call responsible for modifying bucket permissions. SOURCE 
https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html

### Data Exposure Confirmation
During the period when the bucket was publicily acessible a text file, OPEN_BUCKET_PLEASE_FIX.txt, was successfully .

The successful upload during public exposure indicates the bucket was actively accessible, there is a potential for unauthorized read / write access and data integrity and confidentialy cannot be assured.

According to AWS, public S3 access combined with write permissions represents a clinical severity miscorcogiuration due to abuse potential, including malware hosting or data poisoning.

### Endpoint Anomaly Detection
Windows host monitoring system identified an endpoint, BSTOLL-L.froth.ly, running a different Windows OS edition than peer systems. 

This deviation may indicate, misconfiguration, legacy system exposure and reduced patch complaince. Heterogenous OS environments increase operational risk and complicate incident containment as confirmed by Microsoft secuirty baseline guidance. SOURCE
https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines

### Overall Impact on Operations
#### Immediate Risks
-Potential unaothrised data access
- Increaesed attack surface via public S3 bucket
- Reduced identitiy assurance due to a non MFA API usage
#### Business and Operational Impact
- Loss of trust in cloud goverance controls
- Potential regulatory implications if sensitive data was stored
- Increase remediation effort and monitrong overhead

### Due Diligence and Investigation Quality
This investigation demonstates due diligence by:
- Using AWS recommened log sources
- Corroborating findings with offical AWS documentation
Ensuring findings are evdience-backed and reproducible
- Aligning detection logic with indsutry best practice

### Recomened Remiation
- Enfronce manadotry MFA for all IAM users
- Enable S3 Block Public Access at account level
- Implement automated CloudTrail alerts
- Conduct periodic ACL audits
- Standardise OS baselines across endpoints

# Incident Handling Reflection
# Installation and Data Preparation
![alt text](image.png)
![alt text](image-1.png)
![alt text](image-2.png)
# Guided Questions
## Question 1
Question:
<br>You're tasked to find the IAM (Identity & Access Management) users that accessed
an AWS service in Frothly's AWS environment.<br> <br>
List out the IAM users that accessed an AWS service (successfully or
unsuccessfully) in Frothly's AWS environment?
<br>
<br>Answer:
![alt text](image-3.png)
![alt text](image-4.png)
![alt text](image-5.png)
![alt text](image-6.png)
![alt text](image-7.png)
![alt text](image-8.png)
## Question 2
Question:
<br>
What field would you use to alert that AWS API activity has occurred without MFA (multi-factor authentication)?
<br>
<br>Answer:
![alt text](image-9.png)
![alt text](image-10.png)
![alt text](image-11.png)
![alt text](image-12.png)
## Question 3
Question:
<br>Look at the source types available in the dataset. There might be one in particular that holds information on hardware, such as processors.
What is the processor number used on the web servers?
<br>
<br>Answer:
![alt text](image-13.png)
![alt text](image-14.png)
![alt text](image-15.png)
![alt text](image-16.png)
## Question 4
Question:
<br> Bud accidentally makes an S3 bucket publicly accessible. What is the
event ID of the API call that enabled public access?
<br>
<br>Answer:
![alt text](image-17.png)
![alt text](image-18.png)
## Question 5
Question:
<br>What is Bud's username?
<br>
<br>Answer:
![alt text](image-19.png)
## Question 6
Question:
<br>What is the name of the S3 bucket that was made publicly accessible?
<br>
<br>Answer: 
![alt text](image-20.png)
## Question 7
Question:
<br>
What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible?
<br>
<br>Answer:
![alt text](image-21.png)
![alt text](image-22.png)
![alt text](image-23.png)
## Question 8
Question:
<br>
What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?
<br>
<br>Answer:
![alt text](image-24.png)
![alt text](image-25.png)
![alt text](image-26.png)
![alt text](image-27.png)
![alt text](image-28.png)
![alt text](image-29.png)
# Conclusion 
# References

![alt text](image-30.png)
![alt text](image-31.png)
![alt text](image-32.png)
![alt text](image-33.png)
![alt text](image-34.png)
![alt text](image-35.png)
![alt text](image-36.png)
![alt text](image-37.png)
![alt text](<Screenshot 2025-12-19 111920.png>)
![alt text](<Screenshot 2025-12-19 113817.png>)
![alt text](<Screenshot 2025-12-19 113846.png>) 
![alt text](<Screenshot 2025-12-19 113952.png>) 
![alt text](<Screenshot 2025-12-19 114034.png>) 
![alt text](<Screenshot 2025-12-19 114124.png>) 
![alt text](<Screenshot 2025-12-19 114142.png>) 
![alt text](<Screenshot 2025-12-19 114303.png>) 
![alt text](<Screenshot 2025-12-19 114320.png>) 
![alt text](<Screenshot 2025-12-19 114339.png>) 
![alt text](<Screenshot 2025-12-19 114406.png>) 
![alt text](<Screenshot 2025-12-19 114424.png>) 
![alt text](<Screenshot 2025-12-19 112310.png>) 
![alt text](<Screenshot 2025-12-19 112421.png>)
![alt text](<Screenshot 2025-12-19 112500.png>) 
![alt text](<Screenshot 2025-12-19 112532.png>)
![alt text](<Screenshot 2025-12-19 112647.png>) 
![alt text](<Screenshot 2025-12-19 112702.png>) 
![alt text](<Screenshot 2025-12-19 113141.png>) 
![alt text](<Screenshot 2025-12-19 113201.png>) 
![alt text](<Screenshot 2025-12-19 113734 ...png>)
![alt text](<Screenshot 2025-12-19 113734v.png>)