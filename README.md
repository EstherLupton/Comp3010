# Comp3010

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Introduction](#introduction)
- [SOC Context & Incident Handling Framework](#soc-context--incident-handling-framework)
  - [SOC Tiers and Responsibilities](#soc-tiers-and-responsibilities)
    - [Tier 1 (Triage and Monitoring)](#tier-1-triage-and-monitoring)
    - [Tier 2 (Incident Investigation)](#tier-2-incident-investigation)
    - [Tier 3 (Threat Hunting and Specialist Expertise)](#tier-3-threat-hunting-and-specialist-expertise)
  - [In Context of the Dataset](#in-context-of-the-dataset)
- [Splunk Installation & Dataset Preparation](#splunk-installation--dataset-preparation)
  - [Installing Splunk](#installing-splunk)
  - [Adding the License](#adding-the-license)
  - [Installing the Dataset](#installing-the-dataset)
  - [Validation of Correct Installation and Setup](#validation-of-correct-installation-and-setup)
  - [Stopping Splunk](#stopping-splunk)
- [Incident Overview](#incident-overview)
  - [Table 1 - Incident Timeline](#table-1---incident-timeline)
  - [Table 2 - Key Indicators of Compromise](#table-2---key-indicators-of-compromise)
- [Guided Investigation Findings](#guided-investigation-findings)
  - [Identity and Access Management Activity](#identity-and-access-management-activity)
  - [Cloud Storage Misconfiguration](#cloud-storage-misconfiguration)
  - [Endpoint Anomaly Detection](#endpoint-anomaly-detection)
  - [Table 3 - Evidence and Best Practices Corroboration](#table-3---evidence-and-best-practices-corroboration)
  - [Table 4 - Damage Assessment](#table-4---damage-assessment)
- [Operational & Business Impact](#operational--business-impact)
  - [Impact on SOC Operations and Resources](#impact-on-soc-operations-and-resources)
  - [Impact on Identity and Access Management (IAM)](#impact-on-identity-and-access-management-iam)
  - [Impact on System Availability and Performance](#impact-on-system-availability-and-performance)
  - [Impact on Business Continuity and Productivity](#impact-on-business-continuity-and-productivity)
  - [Impact on Security Posture and Future Operations](#impact-on-security-posture-and-future-operations)
  - [Reputational and Compliance Considerations](#reputational-and-compliance-considerations)
  - [Overall Operational Impact](#overall-operational-impact)
- [Incident Response & Recovery](#incident-response--recovery)
  - [Detection](#detection)
  - [Route Cause](#route-cause)
  - [Containment](#containment)
  - [Table 5 - Recovery Timeline](#table-5---recovery-timeline)
- [SOC Reflection & Lessons Learned](#soc-reflection--lessons-learned)
  - [Table 6 - Recommendations & Action Plan](#table-6---recommendations--action-plan)
- [Conclusion](#conclusion)
- [Bibliography](#bibliography)

---

# Introduction
This report investigates Boss of the SOC v3 (BOTSv3) dataset, which is a publicly available Splunk Capture the Flag scenario which simulates a cyber-attack against the fictional brewing company Frothly. The Capture the Flag (CTF) is designed for security operational professionals to practice their incident detection and network forensics skills. Analyst are based in the Security Operations Centre (SOC).

---

# SOC Roles & Incident Handling
The BOTSv3 exercise s demonstrates Security Operations Centre (SOC) roles and incident handling methodologies work hand in hand during a cyber incident investigation. Typically, SOC analysts are divided into tiers based on experience and responsibilities (Enoch Agyepong, 2020). Despite the tier structure, many tasks and responsibilities overlap.

---

## SOC Tiers and Responsibilities

### Tier 1 (Triage and Monitoring)

Tier 1 analysts are often the least experienced analysts, deal with most of the communications directed to the SOC, triaging events, initialising investigations and managing most incidents. When an event requires further investigation Tier 1 analysts escalate to Tier 2. 

### Tier 2 (Incident Investigation)

Tier 2 analysts are responsible for more in-depth analysis of the incident and have additional responsibilities like signature turning, device configuration, vulnerability management, configuring log and event collectors.   Once an incident is transferred, Tier 2 manages the ticket until its resolved and closed or escalated to Tier 3. 

### Tier 3 (Threat Hunting and Specialist Expertise)

Tier 3 analysts are usually the most experienced, dealing with the incidents raised by Tier 2, sharing and managing threat intelligence, handling configuration and implementation of security tools. 

### In Context of the Dataset

Within the investigation, these SOC tier responsibilities are reflected in the guided questions. Tier 1 activities are in the initial log review and identification of suspicious activity. Tier 2 requires correlation from multiple log sources, timeline construction, and identification of compromised IAM accounts. Tier 3 undertakes threat hunting and specialist analysis activities, such as interpreting attacker behaviour, assessing impact and identifying security control gaps. This demonstrates how the BOTSv3 exercise models a realistic SOC workflow, with incidents progressing through tiers as analysis depth and complexity increase.

---

# Incident Handling Method

## Splunk Installiation and Data Prepration
Below are step by step instructions which I took to investigate the BOTSv3 dataset. For reproducibility here are the steps:

---

### Installing Splunk

1. Create an account with Splunk Enterprise  

https://www.splunk.com/en_us/products/splunk-enterprise.html

2. Navigate to the Linux download and copy the .tgz wget link. 

https://www.splunk.com/en_us/download/splunk-enterprise.html

![alt text](<Screenshot 2025-12-19 113817.png>)

The .tgz wget link should look a little like this:  

*wget -O splunk-10.0.2-e2d18b4767e9-linux-amd64.tgz "https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-amd64.tgz"*

![alt text](<Screenshot 2025-12-19 113846.png>) 

3. Open Ubuntu Virtual Machine

4. Open terminal on the VM

5. Navigate to the Desktop directory

6. Paste the link into the terminal and execute.

![alt text](<Screenshot 2025-12-19 113952.png>) 

![alt text](<Screenshot 2025-12-19 114034.png>) 

 NOT SURE ![alt text](<Screenshot 2025-12-19 113734v.png>)

7. Install Splunk using the command:  

*sudo tar xvzf splunk-10.0.1-c486717c32b-linux-amd64.tgz -C /opt/*

![alt text](<Screenshot 2025-12-19 114124.png>) 

![alt text](<Screenshot 2025-12-19 114142.png>) 


8. To run Splunk navigate to the directory opt/splunk/bin and use the command:  

*./splunk start --accept-license*

![alt text](<Screenshot 2025-12-19 114303.png>) 

![alt text](<Screenshot 2025-12-19 114320.png>)

![alt text](<Screenshot 2025-12-19 114339.png>) 

9. Sign in using an administrator account  

![alt text](<Screenshot 2025-12-19 114406.png>)

![alt text](<Screenshot 2025-12-19 114406.png>)  

10. Create an administrator account for Splunk

11. Sign in when prompted

12. Follow the link to the locally hosted application

![alt text](<Screenshot 2025-12-19 111920.png>)

---

### Adding the License

1. Whilst inside the Ubuntu Virtual Machine, navigate to the license file stored on the dle

![alt text](image-32.png)

2. Save the file into the downloads

![alt text](image-33.png)

3. Run the splunk application

![alt text](image-34.png)

4. Open settings and then licensing

5. Upload the license from your downloads to your account

![alt text](image-35.png)

![alt text](image-37.png)

---

### Installing the Dataset

1. Whilst inside the VM, navigate to the Boss of the SOC (BOTS) Dataset Version 3 GitHub page  

https://github.com/splunk/botsv3

![alt text](image.png)

2. Download using the link and extract the zip

![alt text](image-38.png)

3. Open terminal and enter the command to become the root:  

*sudo su*

![alt text](image-41.png)

4. Navigate to the Downloads directory

![alt text](image-42.png)

![alt text](image-43.png)

5. Enter the command:  

*cp -r botsv3_data_set /opt/splunk/etc/apps*

![alt text](image-44.png)

6. Navigate into opt/splunk/etc/apps

![alt text](image-45.png)

---

### Validation of Correct Installation and Setup

Theres a range of steps to ensure installation is correct:

1. To verify Splunk is running you will be able to access it by the web interface typically at http://localhost:8000, to start splunk use the command:  

*./splunk start*

2. To confirm the license was correctly applied, navigate to settings, then licensing inside Splunk and see there’s no warnings or violations

3. To check the BOTS V3 Dataset is correctly installed, navigate to the /opt/splunk/etc/apps directory, run the command *ls* and see the dataset file

4. To validate data inside of Splunk, run the following search inside the application:  

*index=botsv3*

---

### Stopping Splunk
Once you are finished investigating use the command *./splunk stop* to terminate Splunk.

![alt text](image-39.png)

![alt text](image-40.png)

---

# Incident Overview
The incident is a simulated cyber-attack against a fake brewing organisation “Frothly”, using the BOTSv3 dataset, the report presents a high-level narrative of the incident focusing on; what occurred, when it occurred and why it is security-signification, detailing findings from the guided investigation questions and providing log-based evidence to support the conclusions.
The investigation identified a cloud-based security incident, which involved misconfigured AWS (Amazon Web Services) resources, suspicious credential activity and endpoint compromise causing data exposure and cryptocurrency mining. The evidence was primarily found in AWS CloudTrail, S3 access logs, endpoint telemetry and the Windows host monitoring data. All this evidence was collated and analysed using Splunk Enterprise.
Detailed Splunk queries, raw event outputs, field extractions, and reproducible evidence are documented in full within the accompanying GitHub repository, in line with SOC investigation best practice. 

---

## Table 1 - Incident Timeline
Events are presented in chronological order to preserve forensic integrity and support incident reconstruction. 

| Time (UTC) | Event ID | Event Summary | Security Significance | SOC Tier Involved |
|------------|----------|---------------|---------------------|-----------------|
| 09:16:12 | CloudTail | IAM user `web-admin` initiates an unexpected AWS API activity, including access to IAM services, without MFA | Indicates probable credential compromise and reduced identity assurance | **Tier 1:** Detected via continuous CloudTrail log monitoring and alert review<br>**Tier 2:** Investigated IAM activity patterns and validated anomalous access |
| 09:16:55 | External Alert | Credentials for `web_admin` identified as publicly exposed on GitHub | Confirms likely source of compromise and increases incident severity | **Tier 2:** Correlated CloudTrail findings with external exposure intelligence<br>**Tier 3:** Provided threat context on credential leakage risk |
| 13:01:46 | ab45689d-69cd-41e7-8705-5350402cf7ac | S3 bucket `frothlywebcode` configured to allow public access | Critical cloud misconfiguration introduces risk of unauthorised data access and data integrity loss | **Tier 1:** Detection via log monitoring<br>**Tier 2:** Analysed CloudTrail `PutBucketAcl` event and identified misconfiguration |
| 13:02:44 | S3 Access Log | `OPEN_BUCKET_PLEASE_FIX.txt` uploaded to publicly accessible S3 bucket | Confirms active public write access, evidence of the exposure window | **Tier 1:** Alert triage<br>**Tier 2:** Reviewed S3 access to confirm successful unauthorised interaction |
| 13:37:33 | winhostmon | Endpoint `BSTOLL-L` identified performing activity consistent with a non-standard OS configuration | Infrastructure inconsistency increases operational and security risk | **Tier 1:** Detected anomaly via Windows host monitoring logs<br>**Tier 2:** Assessed deviation against environment baseline |
| 13:57:54 | CloudTrail | Public access to the S3 bucket removed | Reduces exposure window and mitigates further risk | **Tier 3:** Coordinated containment actions and validated access control restoration |
| Ongoing | Multiple | Additional suspicious endpoint and network activity observed (out of investigation scope) | Suggests broader compromise; documented separately | **Tier 1:** Logged alerts identified during monitoring<br>**Tier 3:** Scoped and documented for future investigation |

---

## Tabe 2 - Key Indicators of Compromise
In this incident, the following are the key indicators that the cloud services had been compromised.

| Indicator | Evidence Observed | Security Significance |
|-----------|-----------------|---------------------|
| Unexpected cloud administrator activity | Sensitive actions like user creation and permission changes | Indicates potential credential compromise |
| IAM access without MFA | API activity performed without MFA | Reduces identity assurance and increases risk of account abuse |
| Publicly exposed cloud storage | Internal or configuration files uploaded to public storage | Introduces risk of unauthorised access and data leakage |
| Unauthorised infrastructure changes | Unexpected changes or creation of cloud resources | Suggests attacker persistence or privilege abuse |
| Untrusted uploads into cloud storage | Successful uploads from an unknown external source | Confirms active unauthorised access |
| Endpoint configuration inconsistencies | Systems running non-standard OS versions | Increases operational and security risk |
| Reconnaissance activity | Queries or access patterns targeting internal or sensitive data | Indicates attacker discovery and targeting phase |
| Indicators of data exposure | Public access settings or suspicious file transfers | Confirms potential loss of confidentiality and integrity |

---

# Guided Investigation Findings

---

## Guided Questions and Answers
### Question 1
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

### Question 2
Question:
<br>
What field would you use to alert that AWS API activity has occurred without MFA (multi-factor authentication)?
<br>
<br>Answer:
![alt text](image-9.png)
![alt text](image-10.png)
![alt text](image-11.png)
![alt text](image-12.png)

### Question 3
Question:
<br>Look at the source types available in the dataset. There might be one in particular that holds information on hardware, such as processors.
What is the processor number used on the web servers?
<br>
<br>Answer:
![alt text](image-13.png)
![alt text](image-14.png)
![alt text](image-15.png)
![alt text](image-16.png)

### Question 4
Question:
<br> Bud accidentally makes an S3 bucket publicly accessible. What is the
event ID of the API call that enabled public access?
<br>
<br>Answer:
![alt text](image-17.png)
![alt text](image-18.png)

### Question 5
Question:
<br>What is Bud's username?
<br>
<br>Answer:
![alt text](image-19.png)

### Question 6
Question:
<br>What is the name of the S3 bucket that was made publicly accessible?
<br>
<br>Answer: 
![alt text](image-20.png)

### Question 7
Question:
<br>
What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible?
<br>
<br>Answer:
![alt text](image-21.png)
![alt text](image-22.png)
![alt text](image-23.png)

### Question 8
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

---

## Indentity and Access Management Activity
Analysis of AWS CloudTrail logs revealed unusual IAM activity involving multiple user accounts, notably the web_admin. This account performed sensitive AWS and API actions and accessed IAM and S3 services. The timing and nature of these actions indicated the account had been compromised rather than legitimate admin actions.
Additional analysis confirmed several IAM API calls were executed without multifactor authentication, significantly reduced identity assurance.

--- 

## Cloud Storage Misconfiguration
CloudTrail investigations identified an API call (PutBucketAcl) that modified permissions on the S3 bucket frothlywebcode, making it publicly available. This misconfiguration introduced a fatal risk, allowing unauthorised access to cloud-hosted resources.
Analysis of S3 access logs confirmed interaction with the public bucket, including an upload of a file named OPEN_BUCKET_PLEASE_FIX.txt. This proves the bucket was exposed and accessible during the misconfiguration window, confirming a loss of data integrity and confidentiality. 

---

## Endpoint Anomaly Detection
Endpoint telemetry from windows monitoring logs revealed the endpoint BSTOLL-L.froth.ly was running a non-standard operating system configuration. This deviation from peer systems suggests either misconfiguration or potential compromise. Hardware telemetry further confirmed it also was operating on an E5-2676 processor, unlike peer environments.
Inconsistent endpoint configurations increase operational risk by complicating patch management and incident containment. The anomaly therefore reduces security posture within the affected environment.

---

## Table 3 - Evidence and Best Practice Corroboration
| Finding Area | Observation | Authoritative Guidance | Relevance |
|--------------|------------|----------------------|-----------|
| IAM Activity | IAM users performed AWS API actions without MFA | AWS CloudTrail records all API calls per IAM identity, including failed attempts ([AWS, Logging IAM and AWS STS API calls with AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)) | Confirms CloudTrail as authoritative source for identity verification |
| MFA Absence | API calls executed without MFA | AWS recommends monitoring MFA usage for sensitive services such as IAM, S3, and EC2 ([AWS, Security best practices in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)) | Lack of MFA significantly increases the risk of credential compromise |
| S3 Misconfiguration | S3 bucket permissions modified using PutBucketAcl | AWS recommends restricting S3 ACLs and enabling Block Public Access to prevent data exposure ([AWS, Blocking public access to your Amazon S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)) | Confirms root cause of public data exposure |
| Data Exposure | Successful external upload to public S3 bucket | AWS classifies public write access as a critical misconfiguration ([AWS, Security best practices for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)) | Confirms loss of integrity and confidentiality |
| Endpoint Anomaly | Endpoint running non-standard OS configuration | Microsoft security baselines recommend consistent OS configurations ([Microsoft Security Baselines](https://learn.microsoft.com/en-us/security/benchmark/)) | Inconsistent systems increase operational and containment risk |
| Infrastructure Context | Servers running E5-2676 processor architecture | Hardware consistency supports accurate baselining | Confirms anomalies are not hardware related |

---

## Table 4 -  Damage Assessment
| Impact Area | Observed Damage | Severity | Rationale |
|------------|----------------|---------|-----------|
| Data Confidentiality | S3 bucket publicly accessible during exposure window | High | Public access allowed potential unauthorized personnel to read cloud-hosted data |
| Data Integrity | Unauthorized file upload to S3 bucket | High | Successful external upload confirms integrity isn’t guaranteed |
| Identity Assurance | IAM activity without MFA | High | Reduces confidence in legitimacy of identity and increases risk of compromised credentials |
| Cloud Governance | Misconfigured S3 access controls | Medium | Indicates breakdown in change control and access governance |
| Infrastructure Integrity | Unexpected or unauthorised infrastructure activity | Medium | Suggests potential manipulation by attackers or misuse of cloud resources |
| Endpoint Security | Non-standard OS configuration identified | Low to Medium | Increases operational risk, complicates patch management and incident handling |
| SOC Operations | Increased investigation and response workload | Medium | Analyst resources diverted from proactive monitoring to threat hunting |
| Business Operations | Potential disruption due to access review and remediation | Low | No confirmed service outage, but recovery actions may delay workflows and productivity |

---

# Operational and Business Impact
The security incident identified in the BOTSv3 dataset would have had significant operational impact on the organisation. It would have affected technical systems, SOC workload, business continuity and overall security posture. While the investigation is on a simulated environment, the attacker activity would disrupt day-to-day operations in a live enterprise setting.

---

## Impact on SOC Operations and Resources
The detection and investigation would increase demand on SOC resources. Tier 1 would continuously monitor logs, triage alerts and manage the incident related tickets, so their capacity to respond to unrelated security events would decrease. Tier 2 analysts would need to conduct deeper investigations, correlate log sources and reconstruct timelines, this is very time-intensive and resource-heavy.
The sustained focus on a single incident could delay response times for other alerts and therefore increasing exposure to additional threats. Tier 3 would further divert specialist resources away from proactive threat hunting and security improvements. 

---

## Impact on Identity and Access Management (IAM)
To contain the incident, affected accounts would need to be disabled with passwords reset and access permissions reviewed. These actions will disrupt legitimate user access and potentially prevent staff from performing their roles until remediation is complete.
Additionally, widespread IAM reviews would be required to uncover any excessive privileges, requiring role adjustments, temporarily slowing business processes while access is revalidated and approved.

---

## Impact on System Availability and Performance
Depending on the attacker’s activity, affected systems may require isolation from the live network for forensic analysis. This could result in downtime or degraded performance. Logging configurations may also be adjusted to better capture system data, this could impact system performance due to higher storage and processing requirements.

---

## Impact on Business Continuity and Productivity
Operational disruptions could reduce staff productivity. Employees may be unable to access systems or data required for their role, leading to delays in business processes. 
Management and technical staff would also need to divert time away from normal duties to support incident response and postmortem activities.

---

## Impact on Security Posture and Future Operations
While disruptive, the incident would expose weakness in security monitoring tools. Addressing these gaps would result in short-term operational overhead. However, these improvements would strengthen the organisation’s long-term security posture by enhancing visibility and reducing time to detect incidents. 
The incident may also trigger updates to current incident response procedures and analyst training, further impacting operational planning and workloads.

---

## Reputational and Compliance Considerations
If the incident involved sensitive data or unauthorized access to critical systems, the company would face reputational damage and potential fines. This would introduce additional operational requirements like internal audits, compliance reporting, stakeholder communication. 

---

## Overall Operational Impact
Overall, the incident would have a multi-layer impact on operations and business. The investigation would consume SOC resources, disrupt user access and system availability, reduce employee productivity and require organisational changed to security controls and processes. This highlights the importance of well-defined incident response procedures and effective detection. 

---

# Incident Response and Recovery

---

## Detection
The incident was detected through systemic log analysis using Splunk, focusing on AWS telemetry sources including CloudTrail and S3 access logs. Queries were used to identify anomalous IAM activity, access control changes, and unauthorized interactions with cloud resources. Detection evidence is documented in the accompanying README to ensure reproducibility and auditability.

---

## Route Cause
An S3 bucket, frothlywebcode, was made publicly accessible by bstoll through the PutBucketAcl API call (Event ID: ab45689d-69cd-41e7-8705-5350402cf7ac) which modifies bucket access permissions.

---

## Containment
Containment focuses on reducing further exposure and limiting affected systems. Public access permissions were removed from the affected bucket and IAM activity was reviewed to identify accounts involved in unauthorised actions.

---

## Recovery Timeline

| Time Relative to Incident | Recovery Action | SOC Tier Involved | Purpose |
|---------------------------|----------------|-----------------|---------|
| T0 | Incident confirmed and scope defined | Tier 1 and Tier 2 | Identify validity of incident and the affected systems/resources |
| T0 + 30 minutes | Public access removed from S3 bucket | Tier 2 | Prevent further unauthorised access and data exposure |
| T0 + 1 hour | IAM users reviewed for unauthorised activity | Tier 2 | Identify credentials which are compromised or misused |
| T0 + 2 hours | Affected IAM credentials rotated or disabled | Tier 2 | Restore identity assurance for credentials |
| T0 + 3 hours | CloudTrail and S3 access logging validated | Tier 2 | Ensure continued visibility of logs during recovery |
| T0 + 4 hours | Deviations in endpoint configurations are documented | Tier 2 and Tier 3 | Support follow-up remediation and risk reduction |
| T0 + 1 Day | Postmortem of incident where control gaps are identified | Tier 3 | Improve preventative controls and detection manually |

---

## SOC Refelection and Lessons Learned
This incident confirms the idea that identity and access management remains a critical attack surface within cloud environments. The absence of enforced multi-factor authentication on privilege IAM accounts, is a critical control gap. Stronger identity controls would have significantly reduced the likelihood and impact of this incident. 
The investigation also emphasises the operational risk of storage misconfiguration. Public S3 access introduced immediate exposure without requiring any advanced attacker techniques, showing simple configuration errors can have severe consequences. It demonstrates the importance of preventative methods and secure-by-default configurations.
Overall, the incident demonstrates that effective SOC operations doesn’t rely solely on detection capability but should include preventive controls and governance to reduce the attack surface and incident frequency. 

---

## Table 6 -  Recommendations and Action Plan
| Recommendation | Action Plan | SOC Tier Ownership | Priority | Expected Benefit | Cost and Effort |
|----------------|------------|-----------------|---------|----------------|----------------|
| Enforce mandatory MFA for all IAM users | Enforce MFA for all IAM users, prioritising privileged and service accounts. Restrict access where MFA is not present | Tier 2 and Tier 3 | High | Reduces risk of compromised credentials and limits the effect of stolen credentials | Low financial cost. Moderate operational effort |
| Enable S3 Block Public Access at account level | Enable account-level S3 Block Public Access to prevent public ACLs and bucket policies by default | Tier 2 | High | Prevent accidental data exposure and unauthorised access to cloud storage | Minimal cost. Low configuration effort |
| Implement automated CloudTrail alerts | Configure automated alerts for high-risk API calls (e.g. PutBucketAcl, IAM changes, and MFA-disable activity) | Tier 1 and Tier 2 | High | Improves detection speed and reduces incident dwell time | Low cost. Moderate implementation effort |
| Conduct periodic ACL audits | Schedule regular reviews of IAM and S3 access controls to identify excessive privileges and misconfigurations | Tier 2 | Medium | Maintain least-privilege access and reduce long-term exposure risk | Low cost. Ongoing operational effort |
| Standardise OS baselines across endpoints | Enforce standard OS builds aligned with security baselines and ensure consistent patch management | Tier 3 | Medium | Reduces attack surface and simplifies monitoring and incident containment | Moderate cost. Medium remediation effort |

---

# Conclusion
This investigation shows a structured and diligent approach to incident analysis within a cloud environment.  Conclusions and recommendations were corroborated using official AWS documentation and aligned with recognised industry best practice. Overall, the investigation reflects a high standard of analytical rigour and mirrors real-world SOC methodologies.

---

# Timeline of Events for Enitire Scenario
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

# Redundant images grave
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
![alt text](image-31.png)
![alt text](image-30.png)
![alt text](image-36.png)
![alt text](image.png)
![alt text](image-1.png)
![alt text](image-2.png)