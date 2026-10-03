"""Bounded, read-only CloudTrail history and delivered gzip-S3 collection.

Callbacks accept one native SDK request mapping. Captures own authentication,
resource lifecycle and redaction; events retain their full native JSON shape.
Missing records mean not observed within these bounds, never native absence.
"""
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
import gzip
import json
import time
from typing import Any, NotRequired, TypedDict


class EventMatch(TypedDict):
    call_label: str | None
    event: dict[str, Any]
    lookup_metadata: NotRequired[dict[str, Any]]
    first_observed_at: NotRequired[str]
    lookup_round: NotRequired[int]
    lookup_page: NotRequired[int]
    lookup_source: NotRequired[str | None]


class CollectionResult(TypedDict):
    events: list[EventMatch]
    pages: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    objects: list[dict[str, Any]]
    missing_request_ids: list[str]
    missing_calls: list[str]
    page_cap_reached: bool
    partial: bool
    boundary: str
    errors: list[dict[str, Any]]
    bounds: dict[str, Any]


NativeCall = Callable[[Mapping[str, Any]], Mapping[str, Any]]
Related = Callable[[Mapping[str, Any]], bool]
BOUNDARY = "Positive observations only; missing records were not observed within the collection bounds and do not establish absence."
_last_lookup_started = 0.0


class CollectionError(RuntimeError):
    """Collection failed; result retains prior records and provider diagnostics."""

    def __init__(self, result: CollectionResult, cause: Exception):
        super().__init__(str(cause))
        self.result = result


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timestamp(value: str | datetime) -> str:
    return value.isoformat() if isinstance(value, datetime) else value


def _result(requests: Mapping[str, str], bounds: dict[str, Any],
            previous: CollectionResult | None = None) -> CollectionResult:
    result: CollectionResult = {
        "events": [], "pages": [], "observations": [], "objects": [],
        "missing_request_ids": list(requests), "missing_calls": list(requests.values()),
        "page_cap_reached": False, "partial": False, "boundary": BOUNDARY,
        "errors": [], "bounds": bounds,
    }
    if previous is not None:
        for field in ("pages", "observations", "objects", "errors"):
            result[field] = list(previous.get(field, []))
        seen: set[str] = set()
        for row in previous.get("events", []):
            event_id = row["event"].get("eventID") or row.get("lookup_metadata", {}).get("EventId")
            if event_id and event_id in seen:
                continue
            result["events"].append({**row, "call_label": requests.get(row["event"].get("requestID"))})
            if event_id:
                seen.add(event_id)
        result["page_cap_reached"] = previous.get("page_cap_reached", False)
        result["partial"] = previous.get("partial", False) or result["page_cap_reached"] or bool(result["errors"])
    return result


def _finish(result: CollectionResult, requests: Mapping[str, str]) -> CollectionResult:
    found = {row["event"].get("requestID") for row in result["events"] if row["call_label"] is not None}
    result["missing_request_ids"] = [request_id for request_id in requests if request_id not in found]
    result["missing_calls"] = [requests[request_id] for request_id in result["missing_request_ids"]]
    return result


def _failure(result: CollectionResult, requests: Mapping[str, str], error: Exception,
             context: Mapping[str, Any]) -> CollectionError:
    diagnostic = {**context, "at": _now(), "type": type(error).__name__, "message": str(error)}
    for name in ("response", "details"):
        value = getattr(error, name, None)
        if value is not None:
            diagnostic[name] = value
    result["errors"].append(diagnostic)
    result["partial"] = True
    return CollectionError(_finish(result, requests), error)


def _bounds(max_pages: int, rounds: int, wait_seconds: float) -> dict[str, Any]:
    if max_pages < 1 or rounds < 1 or wait_seconds < 0:
        raise ValueError("Collection requires positive page/round bounds and nonnegative wait_seconds")
    return {"max_pages": max_pages, "rounds": rounds, "wait_seconds": wait_seconds}


def _record(result: CollectionResult, event: Any, requests: Mapping[str, str],
            related: Related | None, seen: set[str], event_id: str | None = None) -> bool:
    if not isinstance(event, dict):
        raise ValueError("CloudTrail record must be a JSON object")
    event_id = event.get("eventID") or event_id
    if event_id and event_id in seen:
        return False
    label = requests.get(event.get("requestID"))
    if label is None and (related is None or not related(event)):
        return False
    result["events"].append({"call_label": label, "event": event})
    if event_id:
        seen.add(event_id)
    return True


def collect_history(lookup: NativeCall, requests: Mapping[str, str], *,
                    start_time: str | datetime, end_time: str | datetime | None = None,
                    event_sources: Sequence[str] = (), max_pages: int = 20,
                    rounds: int = 1, wait_seconds: float = 30,
                    related: Related | None = None,
                    lookup_attributes: Sequence[Mapping[str, str]] = (),
                    previous: CollectionResult | None = None) -> CollectionResult:
    """Join full management-history records by exact response request ID.

    Each round scans up to max_pages per source, even after every requested ID
    is found: a single request can produce multiple records. Event IDs, not
    request IDs, deduplicate pages/rounds. Lookup calls are paced below AWS's
    two-per-second regional limit. Native EventName filters can instead be
    supplied as lookup_attributes (CloudTrail permits one lookup attribute).
    CollectionError.result preserves partial pages and native error details.
    A previous result resumes the same query scope, retaining prior events,
    lookup envelope metadata and first-observed provenance.
    """
    global _last_lookup_started
    bounds = _bounds(max_pages, rounds, wait_seconds)
    if lookup_attributes and event_sources:
        raise ValueError("Use event_sources or lookup_attributes, not both")
    if len(lookup_attributes) > 1:
        raise ValueError("CloudTrail permits one lookup attribute")
    base: dict[str, Any] = {"StartTime": _timestamp(start_time), "MaxResults": 50}
    if end_time is not None:
        base["EndTime"] = _timestamp(end_time)
    bounds.update(start_time=base["StartTime"], end_time=base.get("EndTime"),
                  event_sources=list(event_sources), lookup_attributes=list(lookup_attributes))
    if previous is not None and previous.get("bounds"):
        if any(previous["bounds"].get(key) != bounds[key]
               for key in ("start_time", "end_time", "event_sources", "lookup_attributes")):
            raise ValueError("Previous collection belongs to another history query")
    result = _result(requests, bounds, previous)
    seen = {event_id for row in result["events"]
            if (event_id := row["event"].get("eventID") or row.get("lookup_metadata", {}).get("EventId"))}
    prior_rounds = max((row.get("round", 0) for row in result["observations"]), default=0)
    context: dict[str, Any] = {"operation": "LookupEvents"}
    try:
        for round_offset in range(1, rounds + 1):
            round_index = prior_rounds + round_offset
            if round_offset > 1:
                time.sleep(wait_seconds)
            for source in event_sources or (None,):
                token = None
                observation = {"at": _now(), "round": round_index, "source": source,
                               "pages": 0, "page_cap_reached": False}
                result["observations"].append(observation)
                for page_index in range(1, max_pages + 1):
                    parameters = dict(base)
                    attributes = ([{"AttributeKey": "EventSource", "AttributeValue": source}]
                                  if source else list(lookup_attributes))
                    if attributes:
                        parameters["LookupAttributes"] = attributes
                    if token:
                        parameters["NextToken"] = token
                    context = {"operation": "LookupEvents", "round": round_index,
                               "source": source, "page": page_index, "request": parameters}
                    delay = 0.6 - (time.monotonic() - _last_lookup_started)
                    if delay > 0:
                        time.sleep(delay)
                    _last_lookup_started = time.monotonic()
                    context["started_at"] = _now()
                    output = lookup(parameters)
                    items = output.get("Events", [])
                    token = output.get("NextToken")
                    page = {**context, "returned": len(items), "matched": 0, "duplicates": 0,
                            "has_next": bool(token), "next_token": token, "finished_at": _now()}
                    if "ResponseMetadata" in output:
                        page["response_metadata"] = output["ResponseMetadata"]
                    result["pages"].append(page)
                    observation["pages"] += 1
                    for item in items:
                        event = json.loads(item["CloudTrailEvent"])
                        event_id = event.get("eventID") if isinstance(event, dict) else None
                        if (event_id or item.get("EventId")) in seen:
                            page["duplicates"] += 1
                        elif _record(result, event, requests, related, seen, item.get("EventId")):
                            page["matched"] += 1
                            result["events"][-1].update(
                                lookup_metadata={key: value for key, value in item.items() if key != "CloudTrailEvent"},
                                first_observed_at=page["finished_at"], lookup_round=round_index,
                                lookup_page=page_index, lookup_source=source)
                    if not token:
                        break
                    if page_index == max_pages:
                        result["page_cap_reached"] = result["partial"] = True
                        observation["page_cap_reached"] = True
    except Exception as error:
        raise _failure(result, requests, error, context) from error
    return _finish(result, requests)


def collect_s3(list_objects: NativeCall, get_object: NativeCall,
               requests: Mapping[str, str], *, bucket: str, prefix: str = "",
               max_pages: int = 20, rounds: int = 1, wait_seconds: float = 30,
               related: Related | None = None,
               previous: CollectionResult | None = None) -> CollectionResult:
    """Read actual gzip JSON Records from bounded S3 ListObjectsV2 pages.

    Body may be bytes or a readable SDK stream, which is always closed. A
    previous result resumes the same bucket/prefix without rereading delivered
    objects; this supports existing multi-account capture schedulers. Only
    successfully decoded objects are marked processed. No management/data
    category inference or secret redaction is performed by the collector.
    """
    bounds = {**_bounds(max_pages, rounds, wait_seconds), "bucket": bucket, "prefix": prefix}
    if previous is not None and previous.get("bounds"):
        if any(previous["bounds"].get(key) != bounds[key] for key in ("bucket", "prefix")):
            raise ValueError("Previous collection belongs to another bucket/prefix")
    result = _result(requests, bounds, previous)
    seen = {row["event"]["eventID"] for row in result["events"] if row["event"].get("eventID")}
    processed = {row["key"] for row in result["objects"]}
    prior_rounds = len(result["observations"])
    context: dict[str, Any] = {"operation": "ListObjectsV2", "bucket": bucket}
    try:
        for round_offset in range(1, rounds + 1):
            if round_offset > 1:
                time.sleep(wait_seconds)
            round_index = prior_rounds + round_offset
            token = None
            observation = {"at": _now(), "round": round_index, "bucket": bucket,
                           "objects": 0, "pages": 0, "page_cap_reached": False}
            result["observations"].append(observation)
            for page_index in range(1, max_pages + 1):
                parameters: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
                if token:
                    parameters["ContinuationToken"] = token
                context = {"operation": "ListObjectsV2", "round": round_index,
                           "page": page_index, "request": parameters}
                output = list_objects(parameters)
                items = output.get("Contents", [])
                token = output.get("NextContinuationToken") if output.get("IsTruncated") else None
                page = {**context, "returned": len(items), "matched": 0,
                        "has_next": bool(output.get("IsTruncated")), "next_token": token}
                if "ResponseMetadata" in output:
                    page["response_metadata"] = output["ResponseMetadata"]
                result["pages"].append(page)
                observation["pages"] += 1
                observation["objects"] += len(items)
                for item in items:
                    key = item["Key"]
                    if key in processed or not key.endswith(".json.gz"):
                        continue
                    context = {"operation": "GetObject", "round": round_index,
                               "page": page_index, "request": {"Bucket": bucket, "Key": key}}
                    response = get_object(context["request"])
                    body = response["Body"]
                    try:
                        compressed = body.read() if hasattr(body, "read") else body
                        document = json.loads(gzip.decompress(compressed))
                    finally:
                        if hasattr(body, "close"):
                            body.close()
                    records = document["Records"]
                    if not isinstance(records, list):
                        raise ValueError("CloudTrail Records must be a JSON array")
                    for event in records:
                        page["matched"] += int(_record(result, event, requests, related, seen))
                    entry = {"key": key, "records": len(records)}
                    if "LastModified" in item:
                        entry["last_modified"] = _timestamp(item["LastModified"])
                    if "ETag" in item:
                        entry["etag"] = item["ETag"]
                    if "ResponseMetadata" in response:
                        entry["response_metadata"] = response["ResponseMetadata"]
                    result["objects"].append(entry)
                    processed.add(key)
                context = {"operation": "ListObjectsV2", "round": round_index,
                           "page": page_index, "request": parameters}
                if output.get("IsTruncated") and not token:
                    raise ValueError("Truncated ListObjectsV2 page omitted NextContinuationToken")
                if not token:
                    break
                if page_index == max_pages:
                    result["page_cap_reached"] = result["partial"] = True
                    observation["page_cap_reached"] = True
    except Exception as error:
        raise _failure(result, requests, error, context) from error
    return _finish(result, requests)
