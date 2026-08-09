import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def base_payload(**overrides):
    payload = {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature-x",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {
                    "owner": "docker",
                    "name": "build-push-action",
                    "ref": "a" * 40,
                },
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }
    payload.update(overrides)
    return payload


def call(payload):
    r = client.post("/release-gate", json=payload)
    assert r.status_code == 200
    return r.json()


def test_fully_safe_preview_promotes():
    result = call(base_payload())
    assert result["decision"] == "promote"
    assert result["violations"] == []


def test_excess_permission():
    payload = base_payload()
    payload["workflow"]["permissions"] = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
        "actions": "write",
    }
    result = call(payload)
    assert "EXCESS_PERMISSION" in result["violations"]
    assert result["decision"] == "block"


def test_wrong_permission_value():
    payload = base_payload()
    payload["workflow"]["permissions"]["contents"] = "write"
    result = call(payload)
    assert "EXCESS_PERMISSION" in result["violations"]


def test_unsafe_pr_trigger():
    payload = base_payload()
    payload["workflow"]["trigger"] = "pull_request_target"
    result = call(payload)
    assert "UNSAFE_PR_TRIGGER" in result["violations"]


def test_tests_incomplete_failing_tests():
    payload = base_payload()
    payload["workflow"]["testsPassed"] = False
    result = call(payload)
    assert "TESTS_INCOMPLETE" in result["violations"]


def test_tests_incomplete_matrix():
    payload = base_payload()
    payload["workflow"]["matrixComplete"] = False
    result = call(payload)
    assert "TESTS_INCOMPLETE" in result["violations"]


def test_tests_incomplete_failfast():
    payload = base_payload()
    payload["workflow"]["failFast"] = True
    result = call(payload)
    assert "TESTS_INCOMPLETE" in result["violations"]


def test_mutable_action_tag():
    payload = base_payload()
    payload["workflow"]["actions"] = [
        {"owner": "docker", "name": "build-push-action", "ref": "v5"}
    ]
    result = call(payload)
    assert "MUTABLE_ACTION" in result["violations"]


def test_mutable_action_short_sha():
    payload = base_payload()
    payload["workflow"]["actions"] = [
        {"owner": "docker", "name": "build-push-action", "ref": "abc1234"}
    ]
    result = call(payload)
    assert "MUTABLE_ACTION" in result["violations"]


def test_mutable_action_uppercase_sha_rejected():
    payload = base_payload()
    payload["workflow"]["actions"] = [
        {"owner": "docker", "name": "build-push-action", "ref": "A" * 40}
    ]
    result = call(payload)
    assert "MUTABLE_ACTION" in result["violations"]


def test_actions_owner_tag_is_fine():
    payload = base_payload()
    payload["workflow"]["actions"] = [
        {"owner": "actions", "name": "setup-node", "ref": "v4"}
    ]
    result = call(payload)
    assert "MUTABLE_ACTION" not in result["violations"]


def test_single_stage_image():
    payload = base_payload()
    payload["image"]["multiStage"] = False
    result = call(payload)
    assert "SINGLE_STAGE_IMAGE" in result["violations"]


def test_root_runtime():
    payload = base_payload()
    payload["image"]["runsAsRoot"] = True
    result = call(payload)
    assert "ROOT_RUNTIME" in result["violations"]


def test_secret_in_layer_arg():
    payload = base_payload()
    payload["image"]["secretMode"] = "arg"
    result = call(payload)
    assert "SECRET_IN_LAYER" in result["violations"]


def test_secret_in_layer_copy():
    payload = base_payload()
    payload["image"]["secretMode"] = "copy"
    result = call(payload)
    assert "SECRET_IN_LAYER" in result["violations"]


def test_secret_mode_buildkit_is_fine():
    payload = base_payload()
    payload["image"]["secretMode"] = "buildkit"
    result = call(payload)
    assert "SECRET_IN_LAYER" not in result["violations"]


def test_critical_cve():
    payload = base_payload()
    payload["image"]["criticalVulnerabilities"] = 3
    result = call(payload)
    assert "CRITICAL_CVE" in result["violations"]


def test_unpinned_image():
    payload = base_payload()
    payload["image"]["digestPinned"] = False
    result = call(payload)
    assert "UNPINNED_IMAGE" in result["violations"]


def test_production_valid_promotes():
    payload = base_payload(
        target="production",
        event="push",
        ref="refs/heads/main",
    )
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = True
    result = call(payload)
    assert result["decision"] == "promote"
    assert result["violations"] == []


def test_production_invalid_ref():
    payload = base_payload(
        target="production",
        event="push",
        ref="refs/heads/develop",
    )
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = True
    result = call(payload)
    assert "INVALID_PRODUCTION_REF" in result["violations"]


def test_production_wrong_event():
    payload = base_payload(
        target="production",
        event="pull_request",
        ref="refs/heads/main",
    )
    payload["workflow"]["trigger"] = "pull_request"
    payload["workflow"]["environmentApproval"] = True
    result = call(payload)
    assert "INVALID_PRODUCTION_REF" in result["violations"]


def test_production_missing_approval():
    payload = base_payload(
        target="production",
        event="push",
        ref="refs/heads/main",
    )
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = False
    result = call(payload)
    assert "APPROVAL_REQUIRED" in result["violations"]


def test_multi_failure_combination():
    payload = base_payload(
        target="production",
        event="pull_request",
        ref="refs/heads/feature-x",
    )
    payload["workflow"]["trigger"] = "pull_request_target"
    payload["workflow"]["permissions"] = {"contents": "write", "packages": "write", "id-token": "none"}
    payload["workflow"]["testsPassed"] = False
    payload["image"]["runsAsRoot"] = True
    payload["image"]["criticalVulnerabilities"] = 2
    result = call(payload)
    expected = {
        "EXCESS_PERMISSION",
        "UNSAFE_PR_TRIGGER",
        "TESTS_INCOMPLETE",
        "ROOT_RUNTIME",
        "CRITICAL_CVE",
        "INVALID_PRODUCTION_REF",
        "APPROVAL_REQUIRED",
    }
    assert set(result["violations"]) == expected
    assert result["decision"] == "block"
