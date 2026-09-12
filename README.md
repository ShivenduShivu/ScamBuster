# ScamBuster

ScamBuster checks suspicious messages and screenshots for patterns associated with scams. It returns a clear verdict, scam-family classification, specific warning signs, and practical next steps. The analysis pipeline supports both text and images through Amazon Bedrock Nova's multimodal interface.

## Live demo

[Open ScamBuster](http://scambuster-site-063330695992.s3-website-us-east-1.amazonaws.com)

The site is on interim HTTP hosting. A CloudFront and HTTPS upgrade is pending AWS account verification.

## Architecture

```text
User -> S3 website (frontend)
User -> API Gateway -> Lambda -> Bedrock Nova (multimodal)
                                  `-> DynamoDB (anonymous metadata)
```

The repository also includes the private S3 and CloudFront Origin Access Control template for the planned hosting upgrade.

## Privacy design

Message text, screenshot data, and user identifiers are never written to DynamoDB. After a successful check, the backend stores only anonymous operational metadata such as the verdict, confidence, scam family, red-flag types, language, input kind, timestamp, and demo-mode state.

## Cost design

The application uses pay-per-request services: API Gateway HTTP API, Lambda, DynamoDB on-demand, Amazon Bedrock, and S3. The API's default stage is limited to 5 requests per second with a burst of 10, while the handler caps text at 10,000 characters and decoded images at 4 MB. An active $5 monthly AWS Budget sends an email alert when actual cost exceeds 80%.

## Local development

Create and activate a virtual environment, then install the backend dependency:

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
```

Run the analysis cases locally or verify the deployed API:

```powershell
python scripts\local_test.py
python scripts\e2e_test.py --endpoint https://8jk7c14ar6.execute-api.us-east-1.amazonaws.com --table-name ScamBusterChecks
```

Deployment scripts are safely re-runnable:

```powershell
.\scripts\deploy.ps1 -AnalysisMode mock
.\scripts\deploy_frontend.ps1 -Mode s3
# Use -Mode cloudfront after account verification.
```

## Current status

The live API is intentionally in demo mode while AWS completes account verification for Bedrock and CloudFront. The real Bedrock Nova integration code is complete, including multimodal requests, response validation, model fallback, and clean failure handling; its public interface has been tested end to end using the explicit mock mode. Demo responses are labeled in both the page header and result card so they cannot be mistaken for a live model verdict.
