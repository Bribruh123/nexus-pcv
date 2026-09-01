# Copyright: (c) 2022, Daniel Schmidt <danischm@cisco.com>

import json
import logging
import time
from datetime import datetime
from typing import Any

import httpx
import yaml

logger = logging.getLogger(__name__)


def _build_event_entry(anomaly: dict[str, Any], change: str) -> dict[str, Any] | None:
    """Build a report entry from a raw anomaly object.

    'change' is 'raised' for anomalies new after the change or 'cleared' for
    anomalies cleared by the change.
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
        # ND 4.2.1+ serves Insights (NDI) through the unified Analyze API
        self.api_url = f"https://{hostname_ip}/api/v1/analyze"
        self.username = username
        self.password = password
        self.domain = domain
        self.timeout = timeout
        self.session = httpx.Client(verify=False, timeout=120.0)  # nosec B501
        # SSL verification disabled in Client() constructor
        self.authenticated = False

    def _login(self) -> httpx.Response | None:
        """Helper function to authenticate and populate headers"""
        auth_payload = {
            "userName": self.username,
            "userPasswd": self.password,
            "domain": self.domain,
        }
        # ND 4.2.1+ serves login under /api/v1/infra; older releases use /login.
        resp = None
        for path in ("/api/v1/infra/login", "/login"):
            resp = self.session.post(
                f"https://{self.hostname_ip}{path}", json=auth_payload
            )
            if resp.status_code == 200:
                break
        if resp is None or resp.status_code != 200:
            logger.error(f"Login failed: {resp.json() if resp is not None else ''}")
            return resp
        # Nexus Dashboard only accepts the auth cookie for reads; write requests
        # require the JWT as a bearer token header.
        try:
            body = resp.json()
            token = body.get("jwttoken") or body.get("token")
        except Exception:
            token = None
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        self.authenticated = True
        return None

    def get_base_snapshot_id(
        self, site: str
    ) -> tuple[httpx.Response | None, str | None]:
        """Get the latest fabric snapshot ID used as the pre-change base"""
        if not self.authenticated:
            err = self._login()
            if err is not None:
                return err, None

        url = f"{self.api_url}/fabricSnapshots/latest"
        resp = self.session.get(url, params={"fabricName": site})
        if resp.status_code != 200:
            logger.error(f"Get base snapshot failed: {resp.json()}")
            return resp, None

        snapshot_id = resp.json().get("snapshotId")
        if snapshot_id:
            return None, snapshot_id
        logger.error(f"Base snapshot ID could not be found: {resp.json()}")
        return resp, None

    def start_pcv(
        self, name: str, site: str, json_data: str
    ) -> tuple[httpx.Response | None, str | None]:
        """Start pre-change validation and return job ID"""
        if not self.authenticated:
            err = self._login()
            if err is not None:
                return err, None

        err, base_snapshot_id = self.get_base_snapshot_id(site)
        if err is not None:
            return err, None

        data = {
            "name": name,
            "fabricName": site,
            "baseSnapshotId": base_snapshot_id,
            "allowUnsupportedObjectModification": True,
            "uploadedFileName": "tmp.json",
        }
        # 'data' must be a stringified JSON form field, 'file' the proposed change
        form = {
            "data": json.dumps(data),
            "qqfilename": "tmp.json",
            "qqtotalfilesize": str(len(json_data)),
        }
        files = {"file": ("tmp.json", json_data, "application/json")}

        url = f"{self.api_url}/jobs/prechangeAnalysis/file"
        resp = self.session.post(
            url, params={"fabricName": site}, data=form, files=files
        )
        if resp.status_code != 200:
            logger.error(f"Start pre-change analysis failed: {resp.json()}")
            return resp, None

        try:
            job_id = json.loads(resp.content)["data"]["jobId"]
            logger.info(f"Pre-change analysis started. Job ID: {job_id}")
            return None, job_id
        except (KeyError, TypeError):
            pass
        logger.error(f"Job ID could not be found: {resp.json()}")
        return resp, None

    def wait_pcv(
        self, job_id: str
    ) -> tuple[httpx.Response | None, dict[str, str] | None]:
        """Wait for pre-change validation to complete and return job details.

        Returns a dict with the timestamps needed to query anomalies:
        {"baseSnapshotCollectionDate": ..., "analysisTime": ..., "analysisStatus": ...}
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
            data = json.loads(resp.content)
            data = data.get("data", data)
            status = str(data.get("analysisStatus") or "")
            if status.lower() in ("failed", "stopped"):
                error_msg = data.get("errorMessage") or status
                logger.error(f"Pre-change analysis {status}: {error_msg}")
                return resp, None
            # Results are only available once the analysis reaches 'completed'
            if status.lower() == "completed":
                break
            delta_minutes = (datetime.now() - start_time).total_seconds() / 60
            if delta_minutes > self.timeout:
                break
            logger.info("Waiting for pre-change analysis to complete ...")
            time.sleep(10)

        data = json.loads(resp.content)
        data = data.get("data", data)
        logger.info("Pre-change analysis completed.")
        return None, {
            "baseSnapshotCollectionDate": data.get("baseSnapshotCollectionDate", ""),
            "analysisTime": data.get("analysisTime", ""),
            "analysisStatus": status,
        }

    def get_pcv_results(
        self, site: str, job_details: dict[str, str], suppress_events: str
    ) -> tuple[httpx.Response | None, list[Any] | None]:
        """Retrieve anomalies raised and cleared by the pre-change validation.

        Makes two calls to the anomalies endpoint:
        - 'raisedAfterStartDate': anomalies new since the baseline ('raised')
        - 'clearedBeforeEndDate': anomalies cleared by the change ('cleared')
        """
        if not self.authenticated:
            err = self._login()
            if err is not None:
                return err, None

        suppress_events_list = [
            s.strip() for s in suppress_events.split(",") if s.strip()
        ]

        base_params = {
            "fabricName": site,
            "startDate": job_details.get("baseSnapshotCollectionDate", ""),
            "endDate": job_details.get("analysisTime", ""),
            "analysisDate": job_details.get("analysisTime", ""),
            "preChangeAnalysis": "true",
            "includeSystemAnomalies": "false",
            "sort": "severity:desc",
        }
        url = f"{self.api_url}/anomalies/details"

        event_list = []
        for change, param in (
            ("raised", "raisedAfterStartDate"),
            ("cleared", "clearedBeforeEndDate"),
        ):
            resp = self.session.get(
                url, params={**base_params, "anomalySetParam": param}
            )
            if resp.status_code != 200:
                logger.error(f"Get PCV {change} anomalies failed: {resp.json()}")
                return resp, None
            logger.debug(f"PCV {change} anomalies response: {resp.text}")
            try:
                anomalies = json.loads(resp.content).get("anomalies", [])
            except ValueError:
                logger.error(f"Could not parse {change} anomalies: {resp.json()}")
                return resp, None
            for anomaly in anomalies:
                entry = _build_event_entry(anomaly, change)
                if (
                    entry
                    and entry["Severity"] != "info"
                    and entry["AnomalyType"] not in suppress_events_list
                ):
                    event_list.append(entry)

        severity_order = {"critical": 0, "major": 1, "warning": 2, "minor": 3, "info": 4}
        event_list.sort(key=lambda e: severity_order.get(e["Severity"], 5))

        if event_list:
            logger.error(
                "The following anomalies have been raised or cleared by the "
                f"change:\n{yaml.dump(event_list)}"
            )
        return None, event_list

    def get_pcv_url(
        self, site: str, job_id: str
    ) -> tuple[httpx.Response | None, str | None]:
        """Get URL pointing to pre-change validation results"""
        if not self.authenticated:
            err = self._login()
            if err is not None:
                return err, None

        url = (
            f"https://{self.hostname_ip}/analysis-hub/pre-change-analysis/view/"
            f"{site}/{job_id}"
        )

        return None, url
