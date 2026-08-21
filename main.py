from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any

app = FastAPI()


EXPECTED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


class ReleaseGateRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: dict[str, Any]
    image: dict[str, Any]


@app.post("/release-gate")
def release_gate(data: ReleaseGateRequest):
    violations = []

    workflow = data.workflow
    image = data.image

    # 1. Permissions must be exactly least privilege
    if workflow.get("permissions") != EXPECTED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull requests must use pull_request, never pull_request_target
    if data.event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests must pass, matrix must be complete, failFast must be false
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    for action in workflow.get("actions", []):
        owner = action.get("owner", "")
        ref = action.get("ref", "")

        # actions/* may use version tags.
        # Every third-party action needs a full 40-character lowercase SHA.
        if owner != "actions":
            if not (
                len(ref) == 40
                and all(c in "0123456789abcdef" for c in ref)
            ):
                violations.append("MUTABLE_ACTION")
                break

    # 5. Docker image must be multi-stage
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Docker image must run as non-root
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Secrets may only be absent or supplied through BuildKit
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # 8. No critical vulnerabilities
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # 9. Image must be digest pinned
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10 & 11. Production-specific requirements
    if data.target == "production":
        if data.event != "push" or data.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicates while preserving order
    violations = list(dict.fromkeys(violations))

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
