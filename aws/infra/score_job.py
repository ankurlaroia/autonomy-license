"""Score incidents with att/OTel-LLM-8.3B-Classification as a SageMaker training job (S5 GPU step).

    python -m aws.infra.score_job plan                                   # requests only, no AWS calls
    python -m aws.infra.score_job run --data state/data --pilot-check 20 # pilot only: accuracy + score range
    python -m aws.infra.score_job run --data state/data                  # all incidents -> <data>/scores.jsonl
    python -m aws.infra.score_job watch --job al-score-pilot-... --data state/data   # follow a running job

The account has no EC2 GPU quota but does have SageMaker training quota. ml.g5.2xlarge (A10G 24 GB, 32 GB RAM):
ml.g5.xlarge's 16 GB RAM failed to mmap the 16.6 GB weights file (pilot 2026-10-31). The job runs the unchanged model.score_cache with HFClassifierScorer, so the fingerprint matches a
local run. Uploaded to a private bucket in this account: incidents.jsonl, splits.json and the scorer code.
Downloaded: result.json and scores.jsonl (predictions and probabilities, no incident text). The model is
public, so the job holds no token. Nothing here prints incident data.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IMAGE = "763104351884.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.8.0-gpu-py312-cu129-ubuntu22.04-sagemaker-v1.23"
INSTANCE = "ml.g5.2xlarge"   # same A10G as g5.xlarge; 32 GB RAM: the 16.6 GB safetensors file cannot be mmapped in 16 GB
ROLE = "al-sagemaker-scoring"
CODE = ("model/__init__.py", "model/scorer.py", "model/score_cache.py", "common/__init__.py", "common/catalogue.py")
REQUIREMENTS = "transformers==5.2.0\naccelerate>=1.0\nnumpy\npyyaml\n"   # model config: transformers 5.2.0
DATA_FILES = ("incidents.jsonl", "splits.json")
MAX_RUNTIME = 3 * 3600


def bucket_name(account: str, region: str) -> str:
    return f"al-scoring-{account}-{region}"


def trust() -> dict:
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"},
                                                    "Action": "sts:AssumeRole"}]}


def role_policy(account: str, region: str, bucket: str) -> dict:
    """This bucket only; logs and metrics; pull the AWS deep-learning image."""
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket}/*"]},
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": [f"arn:aws:s3:::{bucket}"]},
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
                                       "logs:DescribeLogStreams"],
         "Resource": [f"arn:aws:logs:{region}:{account}:log-group:/aws/sagemaker/TrainingJobs*"]},
        {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
         "Condition": {"StringEquals": {"cloudwatch:namespace": "/aws/sagemaker/TrainingJobs"}}},
        {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
        {"Effect": "Allow", "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
         "Resource": [f"arn:aws:ecr:{region}:763104351884:repository/pytorch-training"]}]}


def source_tar(root: str = ROOT) -> bytes:
    """Scorer code exactly as in the repo, the entry point and requirements. Nothing else."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for rel in CODE:
            t.add(os.path.join(root, rel), arcname=rel)
        t.add(os.path.join(root, "aws", "scoring", "entry.py"), arcname="score_entry.py")
        req = REQUIREMENTS.encode()
        info = tarfile.TarInfo("requirements.txt")
        info.size = len(req)
        t.addfile(info, io.BytesIO(req))
    return buf.getvalue()


def job_request(name: str, role_arn: str, bucket: str, region: str, mode: str, n: int, spot: bool = True) -> dict:
    prefix = f"s3://{bucket}/{name}"
    req = {
        "TrainingJobName": name,
        "AlgorithmSpecification": {"TrainingImage": IMAGE.format(region=region), "TrainingInputMode": "File"},
        "RoleArn": role_arn,
        "HyperParameters": {"sagemaker_program": "score_entry.py",
                            "sagemaker_submit_directory": f"{prefix}/code/source.tar.gz",
                            "sagemaker_region": region, "mode": mode, "n": str(n)},
        "InputDataConfig": [{"ChannelName": "data", "DataSource": {"S3DataSource": {
            "S3DataType": "S3Prefix", "S3Uri": f"{prefix}/data/", "S3DataDistributionType": "FullyReplicated"}}}],
        "OutputDataConfig": {"S3OutputPath": f"{prefix}/output/"},
        "ResourceConfig": {"InstanceType": INSTANCE, "InstanceCount": 1, "VolumeSizeInGB": 80},
        "StoppingCondition": {"MaxRuntimeInSeconds": MAX_RUNTIME},
        "Environment": {"HF_HOME": "/tmp/hf", "HF_HUB_DISABLE_TELEMETRY": "1"},
        "Tags": [{"Key": "project", "Value": "autonomy-license"}]}
    if spot:
        req["EnableManagedSpotTraining"] = True
        req["StoppingCondition"]["MaxWaitTimeInSeconds"] = MAX_RUNTIME + 3600
    return req


def plan(region: str = "us-east-1", account: str = "123456789012") -> list[tuple[str, dict]]:
    b = bucket_name(account, region)
    arn = f"arn:aws:iam::{account}:role/{ROLE}"
    return [("iam.create_role", {"RoleName": ROLE, "AssumeRolePolicyDocument": json.dumps(trust())}),
            ("iam.put_role_policy", {"RoleName": ROLE, "PolicyName": "scoring",
                                     "PolicyDocument": json.dumps(role_policy(account, region, b))}),
            ("sagemaker.create_training_job", job_request("al-score-pilot-0", arn, b, region, "pilot", 20))]


class Runner:   # pragma: no cover - needs AWS
    def __init__(self, region: str, profile: str | None = None):
        import boto3
        self.s = boto3.session.Session(profile_name=profile, region_name=region)
        self.region = region
        self.account = self.s.client("sts").get_caller_identity()["Account"]
        self.bucket = bucket_name(self.account, region)
        self.s3, self.iam, self.sm = self.s.client("s3"), self.s.client("iam"), self.s.client("sagemaker")

    def ensure_bucket(self):
        try:
            self.s3.head_bucket(Bucket=self.bucket)
        except self.s3.exceptions.ClientError:
            kw = {} if self.region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": self.region}}
            self.s3.create_bucket(Bucket=self.bucket, **kw)
        self.s3.put_public_access_block(Bucket=self.bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})

    def ensure_role(self) -> str:
        try:
            arn = self.iam.get_role(RoleName=ROLE)["Role"]["Arn"]
        except self.iam.exceptions.NoSuchEntityException:
            arn = self.iam.create_role(RoleName=ROLE, AssumeRolePolicyDocument=json.dumps(trust()))["Role"]["Arn"]
        self.iam.put_role_policy(RoleName=ROLE, PolicyName="scoring",
                                 PolicyDocument=json.dumps(role_policy(self.account, self.region, self.bucket)))
        return arn

    def upload(self, name: str, data: str):
        self.s3.put_object(Bucket=self.bucket, Key=f"{name}/code/source.tar.gz", Body=source_tar())
        for f in DATA_FILES:
            self.s3.upload_file(os.path.join(data, f), self.bucket, f"{name}/data/{f}")

    def run(self, data: str, mode: str, n: int, spot: bool = True) -> dict:
        from aws.infra.deploy import Deployer
        for f in DATA_FILES:
            if not os.path.exists(os.path.join(data, f)):
                raise SystemExit(f"{data} has no {f}; run python -m data.prepare_telelogs first")
        name = f"al-score-{mode}-{time.strftime('%Y%m%d-%H%M%S')}"
        self.ensure_bucket()
        arn = self.ensure_role()
        self.upload(name, data)
        req = job_request(name, arn, self.bucket, self.region, mode, n, spot)
        Deployer.retry(lambda: self.sm.create_training_job(**req), "training job")   # new role propagates
        print("job", name, INSTANCE, "spot" if spot else "on-demand")
        return self.watch(name, data, mode)

    def watch(self, name: str, data: str, mode: str) -> dict:
        """Follow a job (also one started earlier) and fetch its result when it completes."""
        last = None
        while True:
            j = self.sm.describe_training_job(TrainingJobName=name)
            st = (j["TrainingJobStatus"], j.get("SecondaryStatus"))
            if st != last:
                print(" ", *st)
                last = st
            if j["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
                break
            time.sleep(30)
        info = {"job": name, "status": j["TrainingJobStatus"], "billable_seconds": j.get("BillableTimeInSeconds"),
                "training_seconds": j.get("TrainingTimeInSeconds")}
        if j["TrainingJobStatus"] != "Completed":
            raise SystemExit(json.dumps(info | {"reason": j.get("FailureReason")}, indent=1))
        return info | self.fetch(j["ModelArtifacts"]["S3ModelArtifacts"], data, mode)

    def fetch(self, uri: str, data: str, mode: str) -> dict:
        from model.score_cache import retire_stale_prereg
        key = uri.split(f"s3://{self.bucket}/", 1)[1]
        body = self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as t:
            res = json.load(t.extractfile("result.json"))
            if mode == "full":
                with open(os.path.join(data, "scores.jsonl"), "wb") as f:
                    f.write(t.extractfile("scores.jsonl").read())
                res |= retire_stale_prereg(data, res["fingerprint"])
        return {"result": res}


if __name__ == "__main__":   # pragma: no cover - CLI
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["plan", "run", "watch"])
    ap.add_argument("--job", help="watch: training job name")
    ap.add_argument("--data", default="state/data")
    ap.add_argument("--pilot-check", type=int, default=0)
    ap.add_argument("--on-demand", action="store_true", help="skip spot (faster start, about 3x the price)")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--profile")
    a = ap.parse_args()
    if a.cmd == "plan":
        for op, req in plan(a.region):
            print(op, json.dumps(req, indent=1))
    elif a.cmd == "watch":
        mode = "pilot" if "-pilot-" in a.job else "full"
        print(json.dumps(Runner(a.region, a.profile).watch(a.job, a.data, mode), indent=1))
    else:
        mode = "pilot" if a.pilot_check else "full"
        print(json.dumps(Runner(a.region, a.profile).run(a.data, mode, a.pilot_check or 0, not a.on_demand), indent=1))
