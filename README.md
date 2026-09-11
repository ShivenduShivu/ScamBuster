# ScamBuster

ScamBuster is a web application that analyzes suspicious messages and screenshots for scam patterns using Amazon Bedrock, explains the likely scam family and specific red flags, and recommends practical next actions.

## Architecture

```text
Frontend -> API Gateway HTTP API -> Lambda -> Amazon Bedrock
                                         `-> DynamoDB
```

The API accepts suspicious message text or screenshots. Lambda validates the request, invokes Amazon Bedrock for analysis, and writes only anonymized verdict metadata to DynamoDB.

Status: in development
