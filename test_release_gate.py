from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


SAFE_PAYLOAD = {
    "target": "production",
    "event": "push",
    "ref": "refs/heads/main",
    "workflow": {
        "trigger": "push",
        "permissions": {
            "contents": "read",
            "packages": "write",
            "id-token": "none"
        },
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {
                "owner": "actions",
                "name": "checkout",
                "ref": "v4"
            },
            {
                "owner": "thirdparty",
                "name": "example",
                "ref": "0123456789abcdef0123456789abcdef01234567"
            }
        ],
        "environmentApproval": True
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True
    }
}


def test_safe_production():
    response = client.post("/release-gate", json=SAFE_PAYLOAD)

    assert response.status_code == 200
    assert response.json() == {
        "decision": "promote",
        "violations": []
    }


def test_excess_permission():
    payload = SAFE_PAYLOAD.copy()
    payload["workflow"] = {
        **SAFE_PAYLOAD["workflow"],
        "permissions": {
            "contents": "write",
            "packages": "write",
            "id-token": "none"
        }
    }

    result = client.post("/release-gate", json=payload).json()

    assert result["decision"] == "block"
    assert "EXCESS_PERMISSION" in result["violations"]


def test_unsafe_pr_trigger():
    payload = SAFE_PAYLOAD.copy()
    payload["target"] = "preview"
    payload["event"] = "pull_request"
    payload["ref"] = "refs/heads/feature"
    payload["workflow"] = {
        **SAFE_PAYLOAD["workflow"],
        "trigger": "pull_request_target"
    }

    result = client.post("/release-gate", json=payload).json()

    assert result["decision"] == "block"
    assert "UNSAFE_PR_TRIGGER" in result["violations"]


def test_incomplete_tests():
    payload = SAFE_PAYLOAD.copy()
    payload["workflow"] = {
        **SAFE_PAYLOAD["workflow"],
        "testsPassed": False
    }

    result = client.post("/release-gate", json=payload).json()

    assert result["decision"] == "block"
    assert "TESTS_INCOMPLETE" in result["violations"]


def test_mutable_third_party_action():
    payload = SAFE_PAYLOAD.copy()
    payload["workflow"] = {
        **SAFE_PAYLOAD["workflow"],
        "actions": [
            {
                "owner": "thirdparty",
                "name": "example",
                "ref": "v1"
            }
        ]
    }

    result = client.post("/release-gate", json=payload).json()

    assert result["decision"] == "block"
    assert "MUTABLE_ACTION" in result["violations"]


def test_image_security():
    payload = SAFE_PAYLOAD.copy()
    payload["image"] = {
        "multiStage": False,
        "runsAsRoot": True,
        "secretMode": "copy",
        "criticalVulnerabilities": 2,
        "digestPinned": False
    }

    result = client.post("/release-gate", json=payload).json()

    assert result["decision"] == "block"

    assert "SINGLE_STAGE_IMAGE" in result["violations"]
    assert "ROOT_RUNTIME" in result["violations"]
    assert "SECRET_IN_LAYER" in result["violations"]
    assert "CRITICAL_CVE" in result["violations"]
    assert "UNPINNED_IMAGE" in result["violations"]


def test_production_requirements():
    payload = SAFE_PAYLOAD.copy()

    payload["event"] = "push"
    payload["ref"] = "refs/heads/dev"
    payload["workflow"] = {
        **SAFE_PAYLOAD["workflow"],
        "environmentApproval": False
    }

    result = client.post("/release-gate", json=payload).json()

    assert result["decision"] == "block"
    assert "INVALID_PRODUCTION_REF" in result["violations"]
    assert "APPROVAL_REQUIRED" in result["violations"]
