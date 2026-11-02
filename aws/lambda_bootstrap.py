"""Build the Trusted bundle inside an AWS Lambda from environment variables.

Env:
  AL_DATA_DIR               incidents + scores (e.g. /var/task/bundle/data from the package, or /tmp after an S3 copy)
  AL_DB                     local SQLite path, default /tmp/al.db
  AL_DB_SEED                optional SQLite file shipped in the package; copied to AL_DB at cold start when AL_DB
                            does not exist yet (smoke test: carries the stub licence)
  AL_ISSUER_KMS_KEY         asymmetric KMS key id for the licence issuer public key (real licence), or
  AL_ISSUER_PUBLIC_KEY_PEM  PEM of the issuer public key (smoke-test stub licence). Exactly one is required.
  AL_EXPECTED_FINGERPRINT   from the deployment registry, never from the agent
  AL_LOG_EVENT_SHAPE=1      log the structure (keys and types, never values) of each event and context
  AL_DDB_PREFIX             when set, licence status, warnings, changed cells and approvals come from the shared
                            DynamoDB tables <prefix>-licences / -warnings / -changes / -approvals instead of SQLite
  AL_GUARDRAIL_ID, AL_GUARDRAIL_VERSION, AL_MODEL_ID  the specialist agent's guardrail and Bedrock model

NOTE: each Lambda gets its own SQLite copy for audit and the simulator. Licence status, warnings, changed cells and
approvals must be shared (a revocation or a decision has to reach every Lambda), so with AL_DDB_PREFIX they live in
DynamoDB.
"""
import functools
import json
import os
import shutil


def issuer_public_key_from_env(env=os.environ):
    """Fail closed: exactly one key source must be configured."""
    kms, pem = env.get("AL_ISSUER_KMS_KEY"), env.get("AL_ISSUER_PUBLIC_KEY_PEM")
    if bool(kms) == bool(pem):
        raise RuntimeError("set exactly one of AL_ISSUER_KMS_KEY or AL_ISSUER_PUBLIC_KEY_PEM")
    if kms:
        from license.signer import KmsSigner
        return KmsSigner(kms).public_key()
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(pem.encode())


def seed_db(env=os.environ) -> str:
    db = env.get("AL_DB", "/tmp/al.db")
    seed = env.get("AL_DB_SEED")
    if seed and not os.path.exists(db):
        os.makedirs(os.path.dirname(db) or ".", exist_ok=True)
        shutil.copyfile(seed, db)
    return db


@functools.lru_cache(maxsize=1)
def trusted_from_env():
    from aws.trusted import Trusted
    from common.store import Store
    fp = os.environ.get("AL_EXPECTED_FINGERPRINT")
    if not fp:
        raise RuntimeError("AL_EXPECTED_FINGERPRINT is required")
    t = Trusted.from_dir(os.environ.get("AL_DATA_DIR", "/tmp/al-data"), Store(seed_db()),
                         issuer_public_key_from_env(), fp)
    prefix = os.environ.get("AL_DDB_PREFIX")
    if prefix:
        import boto3
        from aws.tool_lambda.approvals import DynamoApprovals
        from aws.tool_lambda.ledger import DynamoLedger
        from aws.tool_lambda.models import DynamoModels
        from license.registry_ddb import DynamoRegistry
        t.registry = DynamoRegistry(boto3.client("dynamodb"), prefix)
        t.ledger = DynamoLedger(boto3.client("dynamodb"), prefix)    # cells changed per incident, shared
        t.approvals = DynamoApprovals(boto3.client("dynamodb"), prefix)    # request, decision and change, shared
        t.models = DynamoModels(boto3.client("dynamodb"), prefix)    # a withdrawal reaches every Lambda at once
    if os.environ.get("AL_GUARDRAIL_ID"):     # without it there is no specialist, so ask_agent refuses (fail closed)
        import boto3
        from aws.tool_lambda.team import DEFAULT_MODEL, Specialist
        t.specialist = Specialist(boto3.client("bedrock-runtime"), os.environ["AL_GUARDRAIL_ID"],
                                  os.environ.get("AL_GUARDRAIL_VERSION", ""),
                                  os.environ.get("AL_MODEL_ID", DEFAULT_MODEL))
    return t


def shape(obj, depth=0):
    """Structure of an event with every value replaced by its type name, so logs never carry data."""
    if depth > 6:
        return "..."
    if isinstance(obj, dict):
        return {str(k): shape(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [shape(obj[0], depth + 1), f"len={len(obj)}"] if obj else []
    return type(obj).__name__


def context_shape(context):
    cc = getattr(context, "client_context", None)
    ident = getattr(context, "identity", None)
    return {"client_context.custom": shape(getattr(cc, "custom", None) or {}),
            "client_context.env": shape(getattr(cc, "env", None) or {}),
            "identity": sorted(k for k in dir(ident) if not k.startswith("_")) if ident else None}


def log_shape(name, event, context):
    if os.environ.get("AL_LOG_EVENT_SHAPE") == "1":
        print(json.dumps({"shape_of": name, "event": shape(event), "context": context_shape(context)}))
