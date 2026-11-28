from collections import defaultdict, deque
from datetime import timedelta
from pyhunter.models import Alert


def detect_bruteforce(events, rule):

    # Convert the configured time window into a timedelta
    window = timedelta(seconds=rule.window_seconds)

    # 1. Keep only matching events and group them by source IP
    by_source = defaultdict(list)

    for e in events:
        if e.event_type == rule.event_type:
            key = getattr(e, rule.group_by)

            if key:
                by_source[key].append(e)

    alerts = []

    # Analyze each source IP separately
    for source, group in by_source.items():

        # 2. Sort events from oldest to newest
        group.sort(key=lambda e: e.timestamp)

        # Store events inside the current time window
        recent = deque()

        # Remember the window with the most failed attempts
        best = []

        for e in group:

            # 3. Add the new event to the right side
            recent.append(e)

            # 4. Remove events older than the allowed time window
            while e.timestamp - recent[0].timestamp > window:
                recent.popleft()

            # 5. Keep the window with the highest number of events
            if len(recent) > len(best):
                best = list(recent)

        # 6. Generate an alert if the threshold is reached
        if len(best) >= rule.threshold:
            alerts.append(Alert(
                rule_name=rule.name,
                severity=rule.severity,
                mitre_id=rule.mitre,
                src_ip=source,
                first_seen=best[0].timestamp,
                last_seen=best[-1].timestamp,
                count=len(best),
                evidence=best,
            ))

    # Return all generated alerts
    return alerts