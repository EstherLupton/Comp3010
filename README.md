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
