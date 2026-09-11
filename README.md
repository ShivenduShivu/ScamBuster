# ScamBuster

ScamBuster is a web application that analyzes suspicious messages and screenshots for scam patterns using Amazon Bedrock, explains the likely scam family and specific red flags, and recommends practical next actions.

## Architecture

```text
User -> CloudFront -> S3 (static site)
User -> API Gateway -> Lambda -> Bedrock Nova + DynamoDB
```

The browser application is stored in a private S3 bucket and served through CloudFront. The API accepts suspicious message text or screenshots; Lambda validates the request, invokes Amazon Bedrock for analysis, and writes only anonymized verdict metadata to DynamoDB.

Live site: pending CloudFront account verification.

Status: in development
