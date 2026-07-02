# Copyright: (c) 2022, Daniel Schmidt <danischm@cisco.com>

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from nexus_pcv.ndi import NDI

pytestmark = pytest.mark.unit


@pytest.fixture
def ndi() -> NDI:
    return NDI("test.example.com", "admin", "password", "local", 60)


@pytest.fixture
def mock_session(ndi: NDI) -> MagicMock:
    """Mock httpx.Client for NDI"""
    mock = MagicMock(spec=httpx.Client)
    ndi.session = mock
    return mock


def test_ndi_init():
    """Test NDI initialization with correct API base URL"""
    ndi = NDI("192.168.1.1", "admin", "pass", "local", 30)
    assert ndi.hostname_ip == "192.168.1.1"
    assert ndi.api_url == "https://192.168.1.1/api/v1/analyze"
    assert ndi.username == "admin"
    assert ndi.password == "pass"
    assert ndi.domain == "local"
    assert ndi.timeout == 30
    assert ndi.authenticated is False


def test_start_pcv_success(ndi: NDI, mock_session: MagicMock):
    """Test successful PCV job start"""
    ndi.authenticated = True

    snapshot_resp = MagicMock()
    snapshot_resp.status_code = 200
    snapshot_resp.content = json.dumps({"snapshotId": "snap-abc123"}).encode()
    snapshot_resp.json.return_value = {"snapshotId": "snap-abc123"}

    post_resp = MagicMock()
    post_resp.status_code = 200
    post_resp.json.return_value = {"data": {"jobId": "job-123"}}
    post_resp.content = json.dumps({"data": {"jobId": "job-123"}}).encode()

    mock_session.get.return_value = snapshot_resp
    mock_session.post.return_value = post_resp

    err, job_id = ndi.start_pcv("test-job", "group1", "site1", '{"test": "data"}')

    assert err is None
    assert job_id == "job-123"
    mock_session.post.assert_called_once()
    call_args = mock_session.post.call_args
    # Verify correct endpoint with fabricName query param
    assert "/api/v1/analyze/jobs/prechangeAnalysis/file" in call_args[0][0]
    assert call_args[1]["params"]["fabricName"] == "site1"
    # Verify qqfilename and qqtotalfilesize are in form data
    files = {field: value for field, value in call_args[1]["files"]}
    assert "qqfilename" in files
    assert "qqtotalfilesize" in files
    # Verify data payload includes baseSnapshotId and fabricName
    data_json = json.loads(dict(call_args[1]["files"])["data"][1])
    assert data_json["baseSnapshotId"] == "snap-abc123"
    assert data_json["fabricName"] == "site1"


def test_start_pcv_failure(ndi: NDI, mock_session: MagicMock):
    """Test PCV job start failure"""
    ndi.authenticated = True

    snapshot_resp = MagicMock()
    snapshot_resp.status_code = 200
    snapshot_resp.content = json.dumps({"snapshotId": "snap-abc123"}).encode()
    snapshot_resp.json.return_value = {"snapshotId": "snap-abc123"}

    post_resp = MagicMock()
    post_resp.status_code = 400
    post_resp.json.return_value = {"error": "Invalid request"}

    mock_session.get.return_value = snapshot_resp
    mock_session.post.return_value = post_resp

    err, job_id = ndi.start_pcv("test-job", "group1", "site1", '{}')

    assert err is not None
    assert job_id is None


def test_start_pcv_snapshot_failure(ndi: NDI, mock_session: MagicMock):
    """Test PCV job start when snapshot lookup fails"""
    ndi.authenticated = True

    snapshot_resp = MagicMock()
    snapshot_resp.status_code = 404
    snapshot_resp.json.return_value = {"error": "Fabric not found"}
    snapshot_resp.content = json.dumps({"error": "Fabric not found"}).encode()
    mock_session.get.return_value = snapshot_resp

    err, job_id = ndi.start_pcv("test-job", "group1", "site1", '{}')

    assert err is not None
    assert job_id is None
    # POST should not have been called since snapshot lookup failed
    mock_session.post.assert_not_called()


def test_wait_pcv_success(ndi: NDI, mock_session: MagicMock):
    """Test successful wait for PCV completion"""
    ndi.authenticated = True
    
    # GET /jobs/prechangeAnalysis/{jobId} returns preChangeVerification directly (no 'data' wrapper)
    response_body = {
        "analysisStatus": "COMPLETED",
        "baseSnapshotCollectionDate": "2026-06-30T17:54:24Z",
        "analysisTime": "2026-06-30T18:13:50Z",
        "jobId": "job-123",
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = response_body
    mock_response.content = json.dumps(response_body).encode()
    mock_session.get.return_value = mock_response
    
    err, job_details = ndi.wait_pcv("job-123")
    
    assert err is None
    assert job_details is not None
    assert job_details["baseSnapshotCollectionDate"] == "2026-06-30T17:54:24Z"
    assert job_details["analysisTime"] == "2026-06-30T18:13:50Z"
    assert job_details["analysisStatus"] == "COMPLETED"


def test_wait_pcv_failure(ndi: NDI, mock_session: MagicMock):
    """Test wait for PCV with API failure"""
    ndi.authenticated = True
    
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.json.return_value = {"error": "Job not found"}
    mock_session.get.return_value = mock_response
    
    err, job_details = ndi.wait_pcv("job-invalid")
    
    assert err is not None
    assert job_details is None


def test_get_pcv_results_success(ndi: NDI, mock_session: MagicMock):
    """Test successful retrieval of PCV results via raisedAfterStartDate."""
    ndi.authenticated = True

    anomalies = [
        {
            "anomalyId": "id-A",
            "category": "connectivity",
            "severity": "critical",
            "anomalyReason": "Link down detected",
            "anomalyType": "LINK_DOWN",
            "anomalySource": "config",
            "anomalyString": "Link Down",
            "mnemonicTitle": "LINK_DOWN",
            "mnemonicDescription": "A link went down",
            "resourceType": "INTERFACE",
            "nodeNames": ["leaf1"],
            "startDate": "2026-06-30T17:54:24Z",
            "endDate": "2026-06-30T18:13:50Z",
            "fabricName": "Pod_1_Fabric_1",
        },
        {
            "anomalyId": "id-B",
            "category": "configuration",
            "severity": "major",
            "anomalyReason": "Bad contract scope",
            "anomalyType": "CONTRACT_SCOPE",
            "anomalySource": "config",
            "anomalyString": "Contract misconfigured",
            "mnemonicTitle": "CONTRACT_SCOPE",
            "mnemonicDescription": "Contract scope error",
            "resourceType": "CONTRACT",
            "nodeNames": [],
            "startDate": "2026-06-30T18:00:00Z",
            "endDate": "2026-06-30T18:13:50Z",
            "fabricName": "Pod_1_Fabric_1",
        },
        {
            "anomalyId": "id-C",
            "category": "telemetry",
            "severity": "info",
            "anomalyReason": "Info event",
            "anomalyType": "INFO_EVENT",
        },
    ]

    cleared_anomaly = {
        "anomalyId": "id-D",
        "category": "configuration",
        "severity": "warning",
        "anomalyReason": "EPG not deployed",
        "anomalyType": "APP_EPG_NOT_DEPLOYED",
        "anomalySource": "config",
        "anomalyString": "EPG Not Deployed",
        "mnemonicTitle": "APP_EPG_NOT_DEPLOYED",
        "mnemonicDescription": "An EPG is not deployed",
        "resourceType": "EPG",
        "nodeNames": ["spine1"],
        "startDate": "2026-06-30T17:00:00Z",
        "endDate": "2026-06-30T18:13:50Z",
        "fabricName": "Pod_1_Fabric_1",
    }

    resp_raised = MagicMock()
    resp_raised.status_code = 200
    resp_raised.content = json.dumps({"anomalies": anomalies}).encode()
    resp_raised.text = json.dumps({"anomalies": anomalies})

    resp_cleared = MagicMock()
    resp_cleared.status_code = 200
    resp_cleared.content = json.dumps({"anomalies": [cleared_anomaly]}).encode()
    resp_cleared.text = json.dumps({"anomalies": [cleared_anomaly]})

    mock_session.get.side_effect = [resp_raised, resp_cleared]

    job_details = {
        "baseSnapshotCollectionDate": "2026-06-30T17:54:24Z",
        "analysisTime": "2026-06-30T18:13:50Z",
    }

    err, events = ndi.get_pcv_results("Pod_1_Fabric_1", job_details, "")

    assert err is None
    assert events is not None
    assert len(events) == 3  # info-level excluded; 2 raised + 1 cleared

    # Sorted by severity: critical first, then major, then warning
    assert events[0]["AnomalyId"] == "id-A"
    assert events[0]["Severity"] == "critical"
    assert events[0]["Category"] == "Connectivity"
    assert events[0]["Description"] == "Link down detected"
    assert events[0]["Change"] == "raised"
    assert "MnemonicTitle" in events[0]
    assert "NodeNames" in events[0]

    assert events[1]["AnomalyId"] == "id-B"
    assert events[1]["Severity"] == "major"
    assert events[1]["Change"] == "raised"

    assert events[2]["AnomalyId"] == "id-D"
    assert events[2]["Severity"] == "warning"
    assert events[2]["Change"] == "cleared"


def test_get_pcv_results_with_suppress_events(ndi: NDI, mock_session: MagicMock):
    """Test that anomalies whose AnomalyType is in the suppress list are filtered out."""
    ndi.authenticated = True

    response_data = {
        "anomalies": [
            {"anomalyId": "id-X", "category": "performance", "severity": "warning",
             "anomalyReason": "High CPU", "anomalyType": "HIGH_CPU"},
            {"anomalyId": "id-Y", "category": "connectivity", "severity": "critical",
             "anomalyReason": "Link down", "anomalyType": "LINK_DOWN"},
        ]
    }

    resp_raised = MagicMock()
    resp_raised.status_code = 200
    resp_raised.content = json.dumps(response_data).encode()
    resp_raised.text = json.dumps(response_data)

    resp_cleared = MagicMock()
    resp_cleared.status_code = 200
    resp_cleared.content = json.dumps({"anomalies": []}).encode()
    resp_cleared.text = json.dumps({"anomalies": []})

    mock_session.get.side_effect = [resp_raised, resp_cleared]

    job_details = {
        "baseSnapshotCollectionDate": "2026-06-30T17:54:24Z",
        "analysisTime": "2026-06-30T18:13:50Z",
    }

    err, events = ndi.get_pcv_results("fabric1", job_details, "HIGH_CPU")

    assert err is None
    assert events is not None
    assert len(events) == 1
    assert events[0]["AnomalyType"] == "LINK_DOWN"
    assert events[0]["Description"] == "Link down"
    assert events[0]["Change"] == "raised"


def test_get_pcv_url(ndi: NDI, mock_session: MagicMock):
    """Test URL generation for PCV results"""
    ndi.authenticated = True
    
    err, url = ndi.get_pcv_url("pod1", "job-456")
    
    assert err is None
    assert url == "https://test.example.com/analysis-hub/pre-change-analysis/view/pod1/job-456"


def test_get_pcv_results_api_call_params(ndi: NDI, mock_session: MagicMock):
    """Verify the anomalies endpoint is called once with anomalySetParam=raisedAfterStartDate."""
    ndi.authenticated = True

    empty_resp = MagicMock()
    empty_resp.status_code = 200
    empty_resp.content = json.dumps({"anomalies": []}).encode()
    empty_resp.text = json.dumps({"anomalies": []})
    mock_session.get.side_effect = [empty_resp, empty_resp]

    job_details = {
        "baseSnapshotCollectionDate": "2026-06-30T17:54:24Z",
        "analysisTime": "2026-06-30T18:13:50Z",
    }

    ndi.get_pcv_results("TestFabric", job_details, "")

    assert mock_session.get.call_count == 2
    call_args_list = mock_session.get.call_args_list

    # Both calls hit the same endpoint
    for call in call_args_list:
        assert "/api/v1/analyze/anomalies/details" in call[0][0]

    # Shared params present in both calls
    for call in call_args_list:
        params = call[1]["params"]
        assert params["fabricName"] == "TestFabric"
        assert params["startDate"] == "2026-06-30T17:54:24Z"
        assert params["endDate"] == "2026-06-30T18:13:50Z"
        assert params["analysisDate"] == "2026-06-30T18:13:50Z"
        assert params["preChangeAnalysis"] == "true"
        assert params["includeSystemAnomalies"] == "false"
        assert params["sort"] == "severity:desc"

    # First call: raisedAfterStartDate; second call: clearedBeforeEndDate
    assert call_args_list[0][1]["params"]["anomalySetParam"] == "raisedAfterStartDate"
    assert call_args_list[1][1]["params"]["anomalySetParam"] == "clearedBeforeEndDate"
