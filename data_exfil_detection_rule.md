```
    DEFINE EXFIL_THRESHOLD_GB = 5
    DEFINE BASELINE_PERIOD = 90 days
    DEFINE CORRELATION_WINDOW = 24 hours
    DEFINE BASELINE_REFRESH_DAYS = 7

    DEFINE approved_external_destinations = LOAD_CONFIG("approved_destinations")
    DEFINE sensitive_buckets = LOAD_CONFIG("sensitive_buckets")
    DEFINE whitelisted_principals = LOAD_CONFIG("automated_workloads")
    DEFINE high_risk_regions = ["CN", "RU", "KP", "IR"]

    DEFINE principal_sessions = PERSISTENT_STORE()
    DEFINE ip_reputation = PERSISTENT_STORE()
    DEFINE presigned_urls = PERSISTENT_STORE()
    DEFINE replication_configs = PERSISTENT_STORE()

    STREAM cloudtrail_events
    STREAM vpc_flow_logs  
    STREAM s3_access_logs
    STREAM kms_events

    DEFINE s3_activity = CACHE(24 hours)
    DEFINE network_egress = CACHE(24 hours)
    DEFINE kms_activity = CACHE(24 hours)

    FUNCTION calculate_baseline(principal, metric_type):
        historical_data = QUERY(principal, metric_type, BASELINE_PERIOD)
        
        IF insufficient_data(historical_data):
            RETURN NULL
        
        threshold = calculate_threshold(historical_data) // This is a fictional function on which we can decide later what can we include
        
        RETURN threshold

    FOR each principal:
        s3_baseline[principal] = calculate_baseline(principal, "s3_bytes")
        egress_baseline[principal] = calculate_baseline(principal, "egress_bytes")

    ON cloudtrail_event WHERE eventName IN ["GetObject", "PutObject"]:
        
        IF is_presigned_url_generation(event):
            STORE presigned_urls:
                principal = event.principal
                bucket = event.bucket
                object_key = event.object
                generated_at = event.timestamp
                expires_at = event.expiration
        
        ELSE IF is_presigned_url_usage(event):
            generation = LOOKUP presigned_urls WHERE:
                bucket = event.bucket
                AND object_key = event.object
                AND generated_at WITHIN 1 hour BEFORE event.timestamp
            
            IF generation EXISTS:
                TRIGGER ALERT:
                    type = "Presigned URL Data Exfiltration"
                    severity = CRITICAL
                    generator = generation.principal
                    download_ip = event.source_ip
                    download_country = GEO(event.source_ip).country
                    bucket = event.bucket
                    object = event.object
                    bytes_transferred = event.bytes
                    generated_at = generation.generated_at
                    downloaded_at = event.timestamp
                    recommended_actions = [
                        "Revoke all sessions for principal",
                        "Review S3 access logs for additional downloads",
                        "Block source IP if malicious",
                        "Disable presigned URL generation for principal"
                    ]

    ON cloudtrail_event WHERE eventName = "PutBucketReplication":
        
        FOR each destination IN event.replication_destinations:
            IF destination.account != event.account:
                
                IF event.bucket IN sensitive_buckets:
                    TRIGGER ALERT:
                        type = "Cross-Account Replication on Sensitive Bucket"
                        severity = CRITICAL
                        principal = event.principal
                        source_bucket = event.bucket
                        destination_bucket = destination.bucket
                        destination_account = destination.account
                        timestamp = event.timestamp
                        recommended_actions = [
                            "Disable replication configuration immediately",
                            "Investigate destination account ownership",
                            "Review all objects potentially replicated",
                            "Revoke principal permissions"
                        ]
                
                STORE replication_configs:
                    source = event.bucket
                    destination = destination.bucket
                    configured_by = event.principal
                    configured_at = event.timestamp

    ON cloudtrail_event WHERE eventName = "PutBucketPolicy":
        
        IF event.policy.Principal = "*" AND event.bucket IN sensitive_buckets:
            TRIGGER ALERT:
                type = "Sensitive Bucket Made Public"
                severity = CRITICAL
                principal = event.principal
                bucket = event.bucket
                policy = event.policy
                timestamp = event.timestamp
                recommended_actions = [
                    "Revert bucket policy immediately",
                    "Enable S3 Block Public Access",
                    "Review bucket access logs",
                    "Revoke principal permissions"
                ]

    ON kms_event WHERE eventName = "Decrypt":
        
        STORE kms_activity:
            principal = event.principal
            session = event.session_id
            timestamp = event.timestamp
        
        s3_events = QUERY s3_activity WHERE:
            session = event.session_id
            AND timestamp WITHIN 5 minutes OF event.timestamp
            AND eventName IN ["GetObject", "SelectObjectContent"]
        
        IF s3_events EXISTS:
            total_bytes = SUM(s3_events.bytes)
            
            IF total_bytes > EXFIL_THRESHOLD_GB:
                TRIGGER ALERT:
                    type = "Large Volume KMS-Encrypted Data Exfiltration"
                    severity = CRITICAL
                    principal = event.principal
                    decrypted_bytes = total_bytes
                    objects = s3_events.object_keys
                    kms_key = event.key_id
                    timestamp = event.timestamp
                    recommended_actions = [
                        "Revoke KMS key access for principal",
                        "Review CloudTrail for all Decrypt calls",
                        "Check if credentials compromised",
                        "Enable MFA for KMS operations"
                    ]

    ON s3_access_log WHERE operation = "GET.OBJECT":
        
        IF log.bucket IN sensitive_buckets AND log.bytes > 1 GB:
            
            vpc_egress = QUERY vpc_flow_logs WHERE:
                source_ip = log.remote_ip
                AND timestamp WITHIN 10 minutes OF log.timestamp
                AND direction = "egress"
            
            IF vpc_egress.total_bytes < (log.bytes * 0.1):
                TRIGGER ALERT:
                    type = "VPC Endpoint Gateway Data Exfiltration"
                    severity = CRITICAL
                    principal = log.requester
                    source_ip = log.remote_ip
                    bucket = log.bucket
                    bytes_transferred = log.bytes
                    vpc_gap_bytes = log.bytes - vpc_egress.total_bytes
                    timestamp = log.timestamp
                    recommended_actions = [
                        "Review VPC Endpoint policies",
                        "Identify instance/resource by IP",
                        "Check for compromised credentials",
                        "Consider restricting VPC Endpoint access"
                    ]

    FUNCTION detect_fragmented_exfil(principal):
        
        s3_events = QUERY cloudtrail_events WHERE:
            principal = principal
            AND eventName IN ["GetObject", "SelectObjectContent"]
            AND timestamp WITHIN LAST 24 hours
            AND bucket IN sensitive_buckets
        
        FOR each object IN UNIQUE(s3_events.objects):
            object_events = FILTER(s3_events, object)
            
            IF COUNT(object_events) > 10:
                time_span = MAX(object_events.timestamps) - MIN(object_events.timestamps)
                total_bytes = SUM(object_events.bytes)
                
                IF time_span > 1 hour AND total_bytes > EXFIL_THRESHOLD_GB:
                    TRIGGER ALERT:
                        type = "Fragmented Data Exfiltration"
                        severity = CRITICAL
                        principal = principal
                        object = object
                        bucket = object_events.bucket
                        request_count = COUNT(object_events)
                        total_bytes = total_bytes
                        time_span_hours = time_span
                        has_range_requests = ANY(object_events.has_range_header)
                        first_request = MIN(object_events.timestamps)
                        last_request = MAX(object_events.timestamps)
                        recommended_actions = [
                            "Revoke principal access immediately",
                            "Review all object access patterns",
                            "Check for automated exfiltration tools",
                            "Enable S3 Object Lock on bucket"
                        ]

    ON cloudtrail_event:
        IF event.principal NOT IN whitelisted_principals:
            
            IF event.eventName IN ["GetObject", "SelectObjectContent", "GetObjectAcl", "HeadObject"]:
                STORE s3_activity:
                    principal = event.principal
                    session = event.session_id
                    bucket = event.bucket
                    object = event.object
                    bytes = event.bytes
                    timestamp = event.timestamp
                    source_ip = event.source_ip
            
            ELSE IF event.eventName IN ["PutBucketReplication", "PutBucketPolicy"]:
                HANDLE replication and policy changes
            
            ELSE IF is_presigned_url_event(event):
                HANDLE presigned URL activity

    ON vpc_flow_log:
        IF flow.direction = "egress" AND flow.action = "ACCEPT":
            STORE network_egress:
                principal = RESOLVE_PRINCIPAL(flow.interface_id)
                destination_ip = flow.destination
                bytes = flow.bytes
                timestamp = flow.timestamp

    EVERY 1 hour:
        
        s3_aggregated = AGGREGATE s3_activity GROUP BY principal, bucket
        egress_aggregated = AGGREGATE network_egress GROUP BY principal, destination_ip
        
        FOR each (principal, bucket) IN s3_aggregated:
            bytes = s3_aggregated[principal][bucket].total_bytes
            baseline = s3_baseline[principal]
            
            IF (baseline AND bytes > baseline) OR bytes > EXFIL_THRESHOLD_GB:
                TRIGGER ALERT:
                    type = "S3 Download Volume Anomaly"
                    severity = CRITICAL
                    principal = principal
                    bucket = bucket
                    bytes_downloaded = bytes
                    baseline_threshold = baseline
                    time_window = "1 hour"
                    timestamp = CURRENT_TIME
                    recommended_actions = [
                        "Investigate principal activity",
                        "Review CloudTrail for all S3 operations",
                        "Check if legitimate batch job",
                        "Consider temporary access restriction"
                    ]
        
        FOR each (principal, destination_ip) IN egress_aggregated:
            bytes = egress_aggregated[principal][destination_ip].total_bytes
            baseline = egress_baseline[principal]
            
            first_time_ip = NOT EXISTS(ip_reputation[destination_ip])
            approved = destination_ip IN approved_external_destinations
            geo = GEO_LOOKUP(destination_ip)
            
            IF ((baseline AND bytes > baseline) OR (first_time_ip AND bytes > 1 GB)) AND NOT approved:
                TRIGGER ALERT:
                    type = "Network Egress Volume Anomaly"
                    severity = CRITICAL
                    principal = principal
                    destination_ip = destination_ip
                    destination_country = geo.country
                    bytes_transferred = bytes
                    baseline_threshold = baseline
                    first_time_destination = first_time_ip
                    is_tor = geo.is_tor
                    is_vpn = geo.is_vpn
                    is_cloud_provider = geo.is_cloud_provider
                    high_risk_region = geo.country IN high_risk_regions
                    time_window = "1 hour"
                    timestamp = CURRENT_TIME
                    recommended_actions = [
                        "Block destination IP immediately if malicious",
                        "Review VPC Flow Logs for full context",
                        "Check threat intelligence feeds",
                        "Investigate principal for compromise"
                    ]
            
            IF first_time_ip:
                STORE ip_reputation[destination_ip]:
                    first_seen = CURRENT_TIME
                    principal = principal

    EVERY 1 hour:
        
        FOR each principal:
            
            recent_alerts = QUERY alerts WHERE:
                principal = principal
                AND timestamp WITHIN LAST 24 hours
            
            alert_types = UNIQUE(recent_alerts.type)
            
            IF COUNT(alert_types) >= 3:
                TRIGGER ALERT:
                    type = "Multi-Vector Data Exfiltration Campaign"
                    severity = CRITICAL
                    principal = principal
                    attack_vectors = alert_types
                    total_alerts = COUNT(recent_alerts)
                    time_span = 24 hours
                    total_s3_bytes = SUM(FILTER(recent_alerts, type CONTAINS "S3").bytes)
                    total_egress_bytes = SUM(FILTER(recent_alerts, type CONTAINS "Egress").bytes)
                    affected_buckets = UNIQUE(recent_alerts.bucket)
                    destination_ips = UNIQUE(recent_alerts.destination_ip)
                    timestamp = CURRENT_TIME
                    recommended_actions = [
                        "IMMEDIATE: Revoke ALL sessions for principal",
                        "IMMEDIATE: Attach deny-all IAM policy",
                        "Enable MFA delete on all affected buckets",
                        "Enable S3 Object Lock",
                        "Export CloudTrail logs (72 hours)",
                        "Snapshot all affected buckets",
                        "Page on-call security engineer",
                        "Initiate incident response procedure",
                        "Review for lateral movement",
                        "Check all resources accessed by principal"
                    ]
            
            detect_fragmented_exfil(principal)
```

This code doesn't calculate threshold, doesn't calculate risk, and doesn't make any kind of automated actions except alerting.
It won't work if previously the logs are not configured, collected and ingested by SIEM.