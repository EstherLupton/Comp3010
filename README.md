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
# Incident Handling Reflection
# Installation and Data Preparation
# Guided Questions
## Question 1
Question:
You're tasked to find the IAM (Identity & Access Management) users that accessed
an AWS service in Frothly's AWS environment.
Refer to the following link to get an idea of what source type you need to query and
what field in the results will have the answer you're seeking.
5
COMP3010 Security Operations & Incident Management
Link: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-fileexamples.html
List out the IAM users that accessed an AWS service (successfully or
unsuccessfully) in Frothly's AWS environment? Answer guidance: Comma
separated without spaces, in alphabetical order. (Example:
ajackson,mjones,tmiller)
Hint: Use aws:cloudtrail as the source type.
Answer:
## Question 2
Question:
The following links are provided to help you with this question.
Links:
• https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucketpublic-access/
• https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatchalarms-for-cloudtrail-additional-examples.html#cloudwatch-alarms-forcloudtrail-no-mfa-example
Make sure you exclude events related to console logins.
It might be a good idea to do a keyword search query on this one. Don't forget to
surround the keyword with asterisks.
What field would you use to alert that AWS API activity has occurred without MFA
(multi-factor authentication)? Answer guidance: Provide the full JSON path.
(Example: iceCream.flavors.traditional)
Hint: Use aws:cloudtrail as the source type.
Answer:
## Question 3
Question:
Look at the source types available in the dataset. There might be one in particular
that holds information on hardware, such as processors.
What is the processor number used on the web servers? Answer guidance: Include
any special characters/punctuation. (Example: The processor number for Intel Core
i7-8650U is i7-8650U.)
Hint: Use hardware as the source type in Splunk Search for find hardware
information such as CPU statistics, hard drives, network interface cards, memory,
and more.
Answer:
## Question 4
Question:
A common misconfiguration involving AWS is publically
accessible S3 buckets. Read the following resource to understand ACLs
and S3 buckets.
Link: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html
Question 4: Bud accidentally makes an S3 bucket publicly accessible. What is the
event ID of the API call that enabled public access? Answer guidance: Include any
special characters/punctuation.
Hint: Use aws:cloudtrail as the source type to search for the PutBucketAcl event.
Answer:
## Question 5
Question:
What is Bud's username?
Answer:
## Question 6
Question:
What is the name of the S3 bucket that was made publicly accessible?
Hint: Use aws:cloudtrail as the source type.
Answer:
## Question 7
Question:
You're tasked with identifying a text file uploaded to the S3 bucket. Here is a link for
more information related to this topic.
Link: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
Since you know the name of the S3 bucket, you should easily find the answer to
this question.
You will need to query a different AWS-related source type. HTTP status code
might be helpful as well.
What is the name of the text file that was successfully uploaded into the S3 bucket
while it was publicly accessible? Answer guidance: Provide just the file name and
extension, not the full path. (Example: filename.docx instead of
/mylogs/web/filename.docx)
Hint: Use aws:s3:accesslogs
Answer:
## Question 8
Question:
What keywords can you start your search with to help identify what data sources
can help you with this?
One of the fields within this source type clearly has the answer, but which is it?
Perhaps expanding upon your search to count on the operating systems and hosts
will be helpful.
What is the FQDN of the endpoint that is running a different Windows operating
system edition than the others?
Hint: Start with winhostmon as the source type.
Answer:
# Conclusion 
# References
![alt text](image.png)
![alt text](image-1.png)
![alt text](image-2.png)
![alt text](image-3.png)
![alt text](image-4.png)
![alt text](image-5.png)
![alt text](image-6.png)
![alt text](image-7.png)
![alt text](image-8.png)
![alt text](image-9.png)
![alt text](image-10.png)
![alt text](image-11.png)
![alt text](image-12.png)
![alt text](image-13.png)
![alt text](image-14.png)
![alt text](image-15.png)
![alt text](image-16.png)
![alt text](image-17.png)
![alt text](image-18.png)
![alt text](image-19.png)
![alt text](image-20.png)
![alt text](image-21.png)
![alt text](image-22.png)
![alt text](image-23.png)
![alt text](image-24.png)
![alt text](image-25.png)
![alt text](image-26.png)
![alt text](image-27.png)
![alt text](image-28.png)
![alt text](image-29.png)
