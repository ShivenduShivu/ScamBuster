# ScamBuster

ScamBuster is a web application that analyzes suspicious messages and screenshots for scam patterns using Amazon Bedrock, explains the likely scam family and specific red flags, and recommends practical next actions.

## Architecture

```text
User -> S3 website (interim static site)
User -> CloudFront -> private S3 (planned HTTPS upgrade)
User -> API Gateway -> Lambda -> Bedrock Nova + DynamoDB
```

The browser application is temporarily served from an S3 website endpoint. The checked-in CloudFront template will move it behind HTTPS with a private S3 origin after AWS account verification. The API accepts suspicious message text or screenshots; Lambda validates the request, invokes Amazon Bedrock for analysis, and writes only anonymized verdict metadata to DynamoDB.

Live site: http://scambuster-site-063330695992.s3-website-us-east-1.amazonaws.com — interim hosting; CloudFront+HTTPS upgrade pending account verification.

Status: in development
