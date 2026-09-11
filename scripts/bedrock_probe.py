import boto3
from botocore.config import Config


CANDIDATE_MODEL_IDS = [
    "us.amazon.nova-2-lite-v1:0",
    "global.amazon.nova-2-lite-v1:0",
    "us.amazon.nova-lite-v1:0",
    "amazon.nova-lite-v1:0",
    "us.amazon.nova-premier-v1:0",
    "us.amazon.nova-micro-v1:0",
    "us.amazon.nova-pro-v1:0",
]


def main() -> None:
    client = boto3.client(
        "bedrock-runtime",
        region_name="us-east-1",
        config=Config(retries={"total_max_attempts": 2, "mode": "adaptive"}),
    )

    for model_id in CANDIDATE_MODEL_IDS:
        try:
            response = client.converse(
                modelId=model_id,
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": "Reply with exactly: OK"}],
                    }
                ],
                inferenceConfig={"maxTokens": 10},
            )
            reply = response["output"]["message"]["content"][0]["text"]
            print(f"{model_id} -> SUCCESS: {reply}")
        except Exception as error:
            print(f"{model_id} -> {type(error).__name__}: {error}")


if __name__ == "__main__":
    main()
