from prometheus_client import Counter, Histogram

HTTP_REQUESTS=Counter('tsa_http_requests_total','HTTP requests',['method','endpoint','status'])
HTTP_DURATION=Histogram('tsa_http_request_duration_seconds','HTTP duration',['method','endpoint'])
RATE_LIMITED=Counter('tsa_rate_limited_total','HTTP 429 responses',['endpoint'])
UPLOAD_BYTES=Counter('tsa_upload_bytes_total','Uploaded bytes')
