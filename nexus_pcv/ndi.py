# Copyright: (c) 2022, Daniel Schmidt <danischm@cisco.com>

import json
import logging
import time
from datetime import datetime
from typing import Any

import httpx
import yaml

logger = logging.getLogger(__name__)


def _build_event_entry(anomaly: dict, change: str) -> dict | None:
    """Build a report entry from a raw anomaly object.

    Args:
        anomaly: Raw anomaly dict from the NDI API.
        change: ``'raised'`` if the anomaly appeared after the pre-change,
                ``'cleared'`` if it was cleared before the end date.

    Returns:
        A flat dict with human-friendly keys, or ``None`` on any parsing error.
    """
    try:
        return {
            "AnomalyId": anomaly.get("anomalyId", ""),
            "Change": change,
            "Category": str(anomaly.get("category", "")).title(),
            "Severity": str(anomaly.get("severity", "")).lower(),
            "AnomalyType": anomaly.get("anomalyType", ""),
            "AnomalySource": anomaly.get("anomalySource", ""),
            "Description": anomaly.get("anomalyReason", ""),
            "Title": anomaly.get("anomalyString", ""),
            "MnemonicTitle": anomaly.get("mnemonicTitle", ""),
            "MnemonicDescription": anomaly.get("mnemonicDescription", ""),
            "ResourceType": anomaly.get("resourceType", ""),
            "NodeNames": anomaly.get("nodeNames") or [],
            "StartDate": anomaly.get("startDate", ""),
            "EndDate": anomaly.get("endDate", ""),
            "FabricName": anomaly.get("fabricName", ""),
        }
    except (AttributeError, TypeError):
        return None


class NDI:
    def __init__(
        self,
        hostname_ip: str,
        username: str,
        password: str,
        domain: str,
        timeout: int,
    ):
        self.hostname_ip = hostname_ip
        self.api_url = f"https://{hostname_ip}/api/v1/analyze"
        self.username = username
        self.password = password
        self.domain = domain
        self.timeout = timeout
        self.session = httpx.Client(verify=False)  # nosec B501
        # SSL verification disabled in Client() constructor
        self.authenticated = False

    def _login(self) -> httpx.Response | None:
        """Helper function to authenticate and populate headers"""
        auth_payload = {
            "userName": self.username,
            "userPasswd": self.password,
            "domain": self.domain,
        }
        url = f"https://{self.hostname_ip}/login"
        resp = self.session.post(url, json=auth_payload)
        if resp.status_code != 200:
            logger.error(f"Login failed: {resp.json()}")
            return resp
        self.authenticated = True
        return None

    def _get_latest_snapshot_id(self, site: str) -> tuple[httpx.Response | None, str | None]:
        """Get the latest finished snapshot ID for the given fabric."""
        url = f"{self.api_url}/fabricSnapshots/latest"
        resp = self.session.get(url, params={"fabricName": site})
        if resp.status_code != 200:
            logger.error(f"Get latest snapshot failed: {resp.json()}")
            return resp, None
        try:
            snapshot_id = json.loads(resp.content)["snapshotId"]
            logger.debug(f"Latest snapshot ID for '{site}': {snapshot_id}")
            return None, snapshot_id
        except KeyError:
            pass
        logger.error(f"Snapshot ID could not be found: {resp.json()}")
        return resp, None

    def start_pcv(
        self, name: str, group: str, site: str, json_data: str
    ) -> tuple[httpx.Response | None, str | None]:
        """Start pre-change validation and return job ID"""
        if not self.authenticated:
            err = self._login()
            if err is not None:
                return err, None

        err, snapshot_id = self._get_latest_snapshot_id(site)
        if err is not None:
            return err, None

        payload = {
            "name": name,
            "fabricName": site,
            "baseSnapshotId": snapshot_id,
            "allowUnsupportedObjectModification": True,
            "uploadedFileName": "tmp.json",
        }

        files = [
            ("data", ("blob", json.dumps(payload), "application/json")),
            ("file", ("tmp.json", json_data, "application/json")),
            ("qqfilename", (None, "tmp.json")),
            ("qqtotalfilesize", (None, str(len(json_data.encode())))),
        ]

        url = f"{self.api_url}/jobs/prechangeAnalysis/file"
        resp = self.session.post(url, files=files, params={"fabricName": site})
        if resp.status_code != 200:
            logger.error(f"Start pre-change analysis failed: {resp.json()}")
            return resp, None

        try:
            job_id = json.loads(resp.content)["data"]["jobId"]
            logger.info(f"Pre-change analysis started. Job ID: {job_id}")
            return None, job_id
        except KeyError:
            pass
        logger.error(f"Job ID could not be found: {resp.json()}")
        return resp, None

    def wait_pcv(
        self, job_id: str
    ) -> tuple[httpx.Response | None, dict[str, str] | None]:
        """Wait for pre-change validation to complete and return job details with timestamps.
        
        Returns: (error_response, {"baseSnapshotCollectionDate": ..., "analysisTime": ..., "analysisStatus": ...})
        """
        if not self.authenticated:
            err = self._login()
            if err is not None:
                return err, None

        status = None
        start_time = datetime.now()
        while True:
            url = f"{self.api_url}/jobs/prechangeAnalysis/{job_id}"
            resp = self.session.get(url)
            if resp.status_code != 200:
                logger.error(f"Get pre-change analysis status failed: {resp.json()}")
                return resp, None
            try:
                # GET /jobs/prechangeAnalysis/{jobId} returns the preChangeVerification
                # object directly (not wrapped in a 'data' key)
                job_data = json.loads(resp.content)
                status = job_data.get("analysisStatus")
                if status == "COMPLETED":
                    break
            except (KeyError, ValueError):
                logger.error(f"Status could not be found: {resp.json()}")
            delta_minutes = (datetime.now() - start_time).total_seconds() / 60
            if delta_minutes > self.timeout:
                break
            logger.info("Waiting for pre-change analysis to complete ...")
            time.sleep(10)

        try:
            job_data = json.loads(resp.content)
            base_snapshot_date = job_data.get("baseSnapshotCollectionDate")
            analysis_time = job_data.get("analysisTime")
            logger.info("Pre-change analysis completed.")
            return None, {
                "baseSnapshotCollectionDate": base_snapshot_date,
                "analysisTime": analysis_time,
                "analysisStatus": status,
            }
        except (KeyError, ValueError):
            pass
        logger.error(f"Job details could not be found: {resp.json()}")
        return resp, None

    def get_pcv_results(
        self, site: str, job_details: dict[str, str], suppress_events: str
    ) -> tuple[httpx.Response | None, list[Any] | None]:
        """Retrieve anomalies raised and cleared by the pre-change validation.

        Makes two calls to the anomalies endpoint:
        - ``anomalySetParam=raisedAfterStartDate``: anomalies new since the baseline (``Change: raised``)
        - ``anomalySetParam=clearedBeforeEndDate``: anomalies cleared before the end date (``Change: cleared``)

        The two result sets are combined into a single list sorted by severity.
        """
        if not self.authenticated:
            err = self._login()
            if err is not None:
                return err, None

        suppress_events_list = [s.strip() for s in suppress_events.split(",") if s.strip()]
        start_date = job_details.get("baseSnapshotCollectionDate", "")
        end_date = job_details.get("analysisTime", "")

        base_params = {
            "fabricName": site,
            "startDate": start_date,
            "endDate": end_date,
            "analysisDate": end_date,
            "preChangeAnalysis": "true",
            "includeSystemAnomalies": "false",
            "sort": "severity:desc",
        }
        url = f"{self.api_url}/anomalies/details"

        # First call: anomalies raised after the start date
        resp_raised = self.session.get(url, params={**base_params, "anomalySetParam": "raisedAfterStartDate"})
        if resp_raised.status_code != 200:
            logger.error(f"Get PCV raised anomalies failed: {resp_raised.json()}")
            return resp_raised, None
        logger.debug(f"PCV raised anomalies response: {resp_raised.text}")

        # Second call: anomalies cleared before the end date
        resp_cleared = self.session.get(url, params={**base_params, "anomalySetParam": "clearedBeforeEndDate"})
        if resp_cleared.status_code != 200:
            logger.error(f"Get PCV cleared anomalies failed: {resp_cleared.json()}")
            return resp_cleared, None
        logger.debug(f"PCV cleared anomalies response: {resp_cleared.text}")

        event_list = []
        try:
            anomalies = json.loads(resp_raised.content).get("anomalies", [])
            for anomaly in anomalies:
                entry = _build_event_entry(anomaly, "raised")
                if entry and entry["Severity"] != "info" and entry["AnomalyType"] not in suppress_events_list:
                    event_list.append(entry)
        except (KeyError, ValueError, AttributeError) as e:
            logger.error(f"Could not parse raised anomalies response: {e}")
            return resp_raised, None

        try:
            anomalies = json.loads(resp_cleared.content).get("anomalies", [])
            for anomaly in anomalies:
                entry = _build_event_entry(anomaly, "cleared")
                if entry and entry["Severity"] != "info" and entry["AnomalyType"] not in suppress_events_list:
                    event_list.append(entry)
        except (KeyError, ValueError, AttributeError) as e:
            logger.error(f"Could not parse cleared anomalies response: {e}")
            return resp_cleared, None

        _severity_order = {"critical": 0, "major": 1, "warning": 2, "minor": 3, "info": 4}
        event_list.sort(key=lambda e: _severity_order.get(e["Severity"], 5))

        if event_list:
            logger.error(
                f"The following anomalies have been raised or cleared by the change:\n{yaml.dump(event_list)}"
            )
        return None, event_list

    def get_pcv_url(self, site: str, job_id: str) -> tuple[httpx.Response | None, str | None]:
        """Get URL pointing to pre-change validation results"""
        if not self.authenticated:
            err = self._login()
            if err is not None:
                return err, None

        url = f"https://{self.hostname_ip}/analysis-hub/pre-change-analysis/view/{site}/{job_id}"

        return None, url
