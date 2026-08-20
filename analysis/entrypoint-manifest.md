# MinIO Server -- Entrypoint Manifest

Deterministic coverage spine extracted from route-registration source only (no handler-body logic audited). Target: `targets/minio` @ this checkout.

Sources parsed (full read): `cmd/api-router.go`, `cmd/admin-router.go`, `cmd/sts-handlers.go`, `cmd/kms-router.go`, `cmd/metrics-router.go`, `cmd/healthcheck-router.go`, `cmd/routers.go`, `cmd/generic-handlers.go`.

## Global middleware order (`cmd/routers.go: globalMiddlewares`, applied via `router.Use(...)` to every router below)

1. `addCustomHeadersMiddleware` -- sets `X-XSS-Protection`, `X-Content-Type-Options`, HSTS, `x-amz-request-id`
2. `httpTracerMiddleware` -- generic tracer, first to see all requests
3. `setAuthMiddleware` (`cmd/auth-handler.go:616`) -- validates the request carries a *supported* auth-type (SigV2/V4, streaming-signed, JWT, STS, or anonymous) and, for signed requests, a valid/unexpired date header. **It does not perform authorization** -- policy/permission checks happen later, inside each handler body (`checkRequestAuthType`, `globalIAMSys.IsAllowed`, etc.), which is out of scope for this registration-only manifest.
4. `setBrowserRedirectMiddleware` -- redirects browser GET/HEAD to console for anonymous requests
5. `setCrossDomainPolicyMiddleware` -- serves `crossdomain.xml` (legacy Flash)
6. `setRequestLimitMiddleware` -- rejects reserved-metadata headers, oversized headers; caps body size
7. `setRequestValidityMiddleware` -- bad-host / `..`/`.` path traversal / multiple-auth-type / reserved-bucket / bucket-name / SSE-C-over-plaintext checks
8. `setUploadForwardingMiddleware` -- site-replication multipart-upload peer forwarding
9. `setBucketForwardingMiddleware` -- federated-DNS bucket forwarding

Router mount order (`cmd/routers.go: configureServerHandler`): [dist-erasure grid/lock/storage/peer/bootstrap handlers if `globalIsDistErasure`] -> `registerAdminRouter(router, true)` -> `registerHealthCheckRouter` -> `registerMetricsRouter` -> `registerSTSRouter` -> `registerKMSRouter` -> `registerAPIRouter` -> `router.Use(globalMiddlewares...)`.

## S3 API router (`cmd/api-router.go`) -- object operations

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| S3-OBJ-001 | HEAD | `/{bucket}/{object:.+}` | `HeadObjectHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-002 | GET | `/{bucket}/{object:.+}?attributes=` | `GetObjectAttributesHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-003 | PUT | `/{bucket}/{object:.+}?partNumber&uploadId (AmzCopySource hdr regex)` | `CopyObjectPartHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-004 | PUT | `/{bucket}/{object:.+}?partNumber&uploadId` | `PutObjectPartHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-005 | GET | `/{bucket}/{object:.+}?uploadId` | `ListObjectPartsHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-006 | POST | `/{bucket}/{object:.+}?uploadId` | `CompleteMultipartUploadHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-007 | POST | `/{bucket}/{object:.+}?uploads=` | `NewMultipartUploadHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-008 | DELETE | `/{bucket}/{object:.+}?uploadId` | `AbortMultipartUploadHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-009 | GET | `/{bucket}/{object:.+}?acl= (dummy)` | `GetObjectACLHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-010 | PUT | `/{bucket}/{object:.+}?acl= (dummy)` | `PutObjectACLHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-011 | GET | `/{bucket}/{object:.+}?tagging=` | `GetObjectTaggingHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-012 | PUT | `/{bucket}/{object:.+}?tagging=` | `PutObjectTaggingHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-013 | DELETE | `/{bucket}/{object:.+}?tagging=` | `DeleteObjectTaggingHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-014 | POST | `/{bucket}/{object:.+}?select=&select-type=2` | `SelectObjectContentHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-015 | GET | `/{bucket}/{object:.+}?retention=` | `GetObjectRetentionHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-016 | GET | `/{bucket}/{object:.+}?legal-hold=` | `GetObjectLegalHoldHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-017 | GET | `/{bucket}/{object:.+}?lambdaArn` | `GetObjectLambdaHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-018 | GET | `/{bucket}/{object:.+}  _(query/matcher: (default))_` | `GetObjectHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-019 | PUT | `/{bucket}/{object:.+}  _(query/matcher: (AmzCopySource hdr regex))_` | `CopyObjectHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-020 | PUT | `/{bucket}/{object:.+}?retention=` | `PutObjectRetentionHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-021 | PUT | `/{bucket}/{object:.+}?legal-hold=` | `PutObjectLegalHoldHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-022 | PUT | `/{bucket}/{object:.+}  _(query/matcher: (AmzSnowballExtract hdr=true))_` | `PutObjectExtractHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-023 | PUT | `/{bucket}/{object:.+}  _(query/matcher: (AmzWriteOffsetBytes hdr; AppendObject rejected))_` | `errorResponseHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-024 | PUT | `/{bucket}/{object:.+}  _(query/matcher: (default))_` | `PutObjectHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-OBJ-025 | DELETE | `/{bucket}/{object:.+}  _(query/matcher: (default))_` | `DeleteObjectHandler` | s3 | s3APIMiddleware() |
| S3-OBJ-026 | POST | `/{bucket}/{object:.+}?restore=` | `PostRestoreObjectHandler` | s3 | s3APIMiddleware() |

## S3 API router -- bucket operations

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| S3-BKT-001 | GET | `/{bucket}?location=` | `GetBucketLocationHandler` | s3 | s3APIMiddleware() |
| S3-BKT-002 | GET | `/{bucket}?policy=` | `GetBucketPolicyHandler` | s3 | s3APIMiddleware() |
| S3-BKT-003 | GET | `/{bucket}?lifecycle=` | `GetBucketLifecycleHandler` | s3 | s3APIMiddleware() |
| S3-BKT-004 | GET | `/{bucket}?encryption=` | `GetBucketEncryptionHandler` | s3 | s3APIMiddleware() |
| S3-BKT-005 | GET | `/{bucket}?object-lock=` | `GetBucketObjectLockConfigHandler` | s3 | s3APIMiddleware() |
| S3-BKT-006 | GET | `/{bucket}?replication=` | `GetBucketReplicationConfigHandler` | s3 | s3APIMiddleware() |
| S3-BKT-007 | GET | `/{bucket}?versioning=` | `GetBucketVersioningHandler` | s3 | s3APIMiddleware() |
| S3-BKT-008 | GET | `/{bucket}?notification=` | `GetBucketNotificationHandler` | s3 | s3APIMiddleware() |
| S3-BKT-009 | GET | `/{bucket}?events (ListenNotification)` | `ListenNotificationHandler` | s3 | s3APIMiddleware(noThrottleS3HFlag,traceHdrsS3HFlag) |
| S3-BKT-010 | GET | `/{bucket}?replication-reset-status= (MinIO ext)` | `ResetBucketReplicationStatusHandler` | s3 | s3APIMiddleware() |
| S3-BKT-011 | GET | `/{bucket}?acl= (dummy)` | `GetBucketACLHandler` | s3 | s3APIMiddleware() |
| S3-BKT-012 | PUT | `/{bucket}?acl= (dummy)` | `PutBucketACLHandler` | s3 | s3APIMiddleware() |
| S3-BKT-013 | GET | `/{bucket}?cors= (dummy)` | `GetBucketCorsHandler` | s3 | s3APIMiddleware() |
| S3-BKT-014 | PUT | `/{bucket}?cors= (dummy)` | `PutBucketCorsHandler` | s3 | s3APIMiddleware() |
| S3-BKT-015 | DELETE | `/{bucket}?cors= (dummy)` | `DeleteBucketCorsHandler` | s3 | s3APIMiddleware() |
| S3-BKT-016 | GET | `/{bucket}?website= (dummy)` | `GetBucketWebsiteHandler` | s3 | s3APIMiddleware() |
| S3-BKT-017 | GET | `/{bucket}?accelerate= (dummy)` | `GetBucketAccelerateHandler` | s3 | s3APIMiddleware() |
| S3-BKT-018 | GET | `/{bucket}?requestPayment= (dummy)` | `GetBucketRequestPaymentHandler` | s3 | s3APIMiddleware() |
| S3-BKT-019 | GET | `/{bucket}?logging= (dummy)` | `GetBucketLoggingHandler` | s3 | s3APIMiddleware() |
| S3-BKT-020 | GET | `/{bucket}?tagging=` | `GetBucketTaggingHandler` | s3 | s3APIMiddleware() |
| S3-BKT-021 | DELETE | `/{bucket}?website=` | `DeleteBucketWebsiteHandler` | s3 | s3APIMiddleware() |
| S3-BKT-022 | DELETE | `/{bucket}?tagging=` | `DeleteBucketTaggingHandler` | s3 | s3APIMiddleware() |
| S3-BKT-023 | GET | `/{bucket}?uploads=` | `ListMultipartUploadsHandler` | s3 | s3APIMiddleware() |
| S3-BKT-024 | GET | `/{bucket}?list-type=2&metadata=true` | `ListObjectsV2MHandler` | s3 | s3APIMiddleware() |
| S3-BKT-025 | GET | `/{bucket}?list-type=2` | `ListObjectsV2Handler` | s3 | s3APIMiddleware() |
| S3-BKT-026 | GET | `/{bucket}?versions&metadata=true` | `ListObjectVersionsMHandler` | s3 | s3APIMiddleware() |
| S3-BKT-027 | GET | `/{bucket}?versions` | `ListObjectVersionsHandler` | s3 | s3APIMiddleware() |
| S3-BKT-028 | GET | `/{bucket}?policyStatus=` | `GetBucketPolicyStatusHandler` | s3 | s3APIMiddleware() |
| S3-BKT-029 | PUT | `/{bucket}?lifecycle=` | `PutBucketLifecycleHandler` | s3 | s3APIMiddleware() |
| S3-BKT-030 | PUT | `/{bucket}?replication=` | `PutBucketReplicationConfigHandler` | s3 | s3APIMiddleware() |
| S3-BKT-031 | PUT | `/{bucket}?encryption=` | `PutBucketEncryptionHandler` | s3 | s3APIMiddleware() |
| S3-BKT-032 | PUT | `/{bucket}?policy=` | `PutBucketPolicyHandler` | s3 | s3APIMiddleware() |
| S3-BKT-033 | PUT | `/{bucket}?object-lock=` | `PutBucketObjectLockConfigHandler` | s3 | s3APIMiddleware() |
| S3-BKT-034 | PUT | `/{bucket}?tagging=` | `PutBucketTaggingHandler` | s3 | s3APIMiddleware() |
| S3-BKT-035 | PUT | `/{bucket}?versioning=` | `PutBucketVersioningHandler` | s3 | s3APIMiddleware() |
| S3-BKT-036 | PUT | `/{bucket}?notification=` | `PutBucketNotificationHandler` | s3 | s3APIMiddleware() |
| S3-BKT-037 | PUT | `/{bucket}?replication-reset= (MinIO ext)` | `ResetBucketReplicationStartHandler` | s3 | s3APIMiddleware() |
| S3-BKT-038 | PUT | `/{bucket}  _(query/matcher: (default, MakeBucket))_` | `PutBucketHandler` | s3 | s3APIMiddleware() |
| S3-BKT-039 | HEAD | `/{bucket}  _(query/matcher: (default))_` | `HeadBucketHandler` | s3 | s3APIMiddleware() |
| S3-BKT-040 | POST | `/{bucket}?(PostPolicy sigv4 MatcherFunc)` | `PostPolicyBucketHandler` | s3 | s3APIMiddleware(traceHdrsS3HFlag) |
| S3-BKT-041 | POST | `/{bucket}?delete= (DeleteMultipleObjects)` | `DeleteMultipleObjectsHandler` | s3 | s3APIMiddleware() |
| S3-BKT-042 | DELETE | `/{bucket}?policy=` | `DeleteBucketPolicyHandler` | s3 | s3APIMiddleware() |
| S3-BKT-043 | DELETE | `/{bucket}?replication=` | `DeleteBucketReplicationConfigHandler` | s3 | s3APIMiddleware() |
| S3-BKT-044 | DELETE | `/{bucket}?lifecycle=` | `DeleteBucketLifecycleHandler` | s3 | s3APIMiddleware() |
| S3-BKT-045 | DELETE | `/{bucket}?encryption=` | `DeleteBucketEncryptionHandler` | s3 | s3APIMiddleware() |
| S3-BKT-046 | DELETE | `/{bucket}  _(query/matcher: (default))_` | `DeleteBucketHandler` | s3 | s3APIMiddleware() |
| S3-BKT-047 | GET | `/{bucket}?replication-metrics=2 (MinIO ext)` | `GetBucketReplicationMetricsV2Handler` | s3 | s3APIMiddleware() |
| S3-BKT-048 | GET | `/{bucket}?replication-metrics= (deprecated)` | `GetBucketReplicationMetricsHandler` | s3 | s3APIMiddleware() |
| S3-BKT-049 | GET | `/{bucket}?replication-check= (MinIO ext)` | `ValidateBucketReplicationCredsHandler` | s3 | s3APIMiddleware() |
| S3-BKT-050 | GET | `/{bucket}  _(query/matcher: (default, ListObjectsV1 legacy))_` | `ListObjectsV1Handler` | s3 | s3APIMiddleware() |

## S3 API router -- rejected object-level sub-resources (`rejectedObjAPIs`)

> Loop registers one route per (methods,query) tuple in `rejectedObjAPIs`; both entries shown here summarize the loop body -- 2 API names (`torrent`, `acl`) x their listed methods.

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| S3-REJO-001 | HEAD/PUT/DELETE/GET (per-entry) | `/{bucket}/{object:.+}?torrent= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJO-002 | DELETE | `/{bucket}/{object:.+}?acl= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |

## S3 API router -- rejected bucket-level sub-resources (`rejectedBucketAPIs`)

> 12 API names in `rejectedBucketAPIs`: inventory, cors, metrics, website, logging, accelerate, requestPayment, acl, publicAccessBlock, ownershipControls, intelligent-tiering, analytics. Each registered with its own method list via `notImplementedHandler`.

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| S3-REJB-001 | (varies per-API) | `/{bucket}?inventory= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-002 | (varies per-API) | `/{bucket}?cors= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-003 | (varies per-API) | `/{bucket}?metrics= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-004 | (varies per-API) | `/{bucket}?website= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-005 | (varies per-API) | `/{bucket}?logging= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-006 | (varies per-API) | `/{bucket}?accelerate= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-007 | (varies per-API) | `/{bucket}?requestPayment= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-008 | (varies per-API) | `/{bucket}?acl= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-009 | (varies per-API) | `/{bucket}?publicAccessBlock= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-010 | (varies per-API) | `/{bucket}?ownershipControls= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-011 | (varies per-API) | `/{bucket}?intelligent-tiering= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |
| S3-REJB-012 | (varies per-API) | `/{bucket}?analytics= or '' -- rejected` | `notImplementedHandler` | s3 | collectAPIStats+httpTraceAll (no s3APIMiddleware) |

## S3 API router -- root operations

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| S3-ROOT-001 | GET | `/?events (root ListenNotification)` | `ListenNotificationHandler` | s3 | s3APIMiddleware(noThrottleS3HFlag,traceHdrsS3HFlag) |
| S3-ROOT-002 | GET | `/  _(query/matcher: (default, ListBuckets))_` | `ListBucketsHandler` | s3 | s3APIMiddleware() |
| S3-ROOT-003 | GET | `//  _(query/matcher: (default, ListBuckets // workaround))_` | `ListBucketsHandler` | s3 | s3APIMiddleware() |

## S3 API router -- catch-all handlers

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| S3-CATCH-001 | * | `*?unmatched path` | `errorResponseHandler` | s3 | collectAPIStats("notfound")+httpTraceAll (catch-all) |
| S3-CATCH-002 | * | `*?unmatched method` | `methodNotAllowedHandler("S3")` | s3 | collectAPIStats("methodnotallowed")+httpTraceAll (catch-all) |

## Admin router (`cmd/admin-router.go`) -- prefix `/minio/admin/v3`

> All paths below are relative to `/minio/admin/v3` (= `adminPathPrefix` `/minio/admin` + `adminAPIVersionPrefix` `/v3`).
> `adminMiddleware(handler, flags...)` flags are `hFlag` bits only (`noGZFlag`/`traceAllFlag`/`noObjLayerFlag`) -- **no per-route action-type / permission flag is passed at registration** in this codebase revision; the required IAM action is resolved deep inside each handler body, not visible at the router.
> `[gated: ...]` marks routes only registered when the noted boolean is true at server-start (`globalIsDistErasure`/`globalIsErasure` for erasure-only ops, `enableConfigOps` for config-KV bulk ops -- `enableConfigOps=true` is hardcoded at the `registerAdminRouter(router, true)` call site in `routers.go`).

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| ADM-001 | POST | `/minio/admin/v3/service?action&type=2` | `ServiceV2Handler` | admin | adminMiddleware(traceAllFlag) |
| ADM-002 | POST | `/minio/admin/v3/service?action (deprecated)` | `ServiceHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-003 | POST | `/minio/admin/v3/update?updateURL&type=2` | `ServerUpdateV2Handler` | admin | adminMiddleware(traceAllFlag) |
| ADM-004 | POST | `/minio/admin/v3/update?updateURL (deprecated)` | `ServerUpdateHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-005 | GET | `/minio/admin/v3/info` | `ServerInfoHandler` | admin | adminMiddleware(traceAllFlag,noObjLayerFlag) |
| ADM-006 | GET,POST | `/minio/admin/v3/inspect-data` | `InspectDataHandler` | admin | adminMiddleware(noGZFlag,traceHdrsS3HFlag[=traceAllFlag]) |
| ADM-007 | GET | `/minio/admin/v3/storageinfo` | `StorageInfoHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-008 | GET | `/minio/admin/v3/datausageinfo` | `DataUsageInfoHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-009 | GET | `/minio/admin/v3/metrics` | `MetricsHandler` | admin | adminMiddleware(traceHdrsS3HFlag[=traceAllFlag]) |
| ADM-010 | POST | `/minio/admin/v3/heal/` | `HealHandler [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-011 | POST | `/minio/admin/v3/heal/{bucket}` | `HealHandler [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-012 | POST | `/minio/admin/v3/heal/{bucket}/{prefix:.*}` | `HealHandler [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-013 | POST | `/minio/admin/v3/background-heal/status` | `BackgroundHealStatusHandler [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-014 | GET | `/minio/admin/v3/pools/list` | `ListPools [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-015 | GET | `/minio/admin/v3/pools/status?pool` | `StatusPool [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-016 | POST | `/minio/admin/v3/pools/decommission?pool` | `StartDecommission [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-017 | POST | `/minio/admin/v3/pools/cancel?pool` | `CancelDecommission [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-018 | POST | `/minio/admin/v3/rebalance/start` | `RebalanceStart [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-019 | GET | `/minio/admin/v3/rebalance/status` | `RebalanceStatus [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-020 | POST | `/minio/admin/v3/rebalance/stop` | `RebalanceStop [gated: `globalIsDistErasure||globalIsErasure`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-021 | POST | `/minio/admin/v3/profiling/start?profilerType (deprecated)` | `StartProfilingHandler` | admin | adminMiddleware(traceAllFlag,noObjLayerFlag) |
| ADM-022 | GET | `/minio/admin/v3/profiling/download` | `DownloadProfilingHandler` | admin | adminMiddleware(traceHdrsS3HFlag[=traceAllFlag],noObjLayerFlag) |
| ADM-023 | POST | `/minio/admin/v3/profile` | `ProfileHandler` | admin | adminMiddleware(traceHdrsS3HFlag[=traceAllFlag],noObjLayerFlag) |
| ADM-024 | GET | `/minio/admin/v3/get-config-kv?key` | `GetConfigKVHandler [gated: `enableConfigOps`]` | admin | adminMiddleware() |
| ADM-025 | PUT | `/minio/admin/v3/set-config-kv` | `SetConfigKVHandler [gated: `enableConfigOps`]` | admin | adminMiddleware() |
| ADM-026 | DELETE | `/minio/admin/v3/del-config-kv` | `DelConfigKVHandler [gated: `enableConfigOps`]` | admin | adminMiddleware() |
| ADM-027 | GET | `/minio/admin/v3/help-config-kv?subSys&key` | `HelpConfigKVHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-028 | GET | `/minio/admin/v3/list-config-history-kv?count` | `ListConfigHistoryKVHandler [gated: `enableConfigOps`]` | admin | adminMiddleware(traceAllFlag) |
| ADM-029 | DELETE | `/minio/admin/v3/clear-config-history-kv?restoreId` | `ClearConfigHistoryKVHandler [gated: `enableConfigOps`]` | admin | adminMiddleware() |
| ADM-030 | PUT | `/minio/admin/v3/restore-config-history-kv?restoreId` | `RestoreConfigHistoryKVHandler [gated: `enableConfigOps`]` | admin | adminMiddleware() |
| ADM-031 | GET | `/minio/admin/v3/config` | `GetConfigHandler [gated: `enableConfigOps`]` | admin | adminMiddleware() |
| ADM-032 | PUT | `/minio/admin/v3/config` | `SetConfigHandler [gated: `enableConfigOps`]` | admin | adminMiddleware() |
| ADM-033 | PUT | `/minio/admin/v3/add-canned-policy?name` | `AddCannedPolicy` | admin | adminMiddleware(traceAllFlag) |
| ADM-034 | GET | `/minio/admin/v3/accountinfo` | `AccountInfoHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-035 | PUT | `/minio/admin/v3/add-user?accessKey` | `AddUser` | admin | adminMiddleware() |
| ADM-036 | PUT | `/minio/admin/v3/set-user-status?accessKey&status` | `SetUserStatus` | admin | adminMiddleware() |
| ADM-037 | PUT | `/minio/admin/v3/add-service-account` | `AddServiceAccount` | admin | adminMiddleware() |
| ADM-038 | POST | `/minio/admin/v3/update-service-account?accessKey` | `UpdateServiceAccount` | admin | adminMiddleware() |
| ADM-039 | GET | `/minio/admin/v3/info-service-account?accessKey` | `InfoServiceAccount` | admin | adminMiddleware() |
| ADM-040 | GET | `/minio/admin/v3/list-service-accounts` | `ListServiceAccounts` | admin | adminMiddleware() |
| ADM-041 | DELETE | `/minio/admin/v3/delete-service-account?accessKey` | `DeleteServiceAccount` | admin | adminMiddleware() |
| ADM-042 | GET | `/minio/admin/v3/temporary-account-info?accessKey` | `TemporaryAccountInfo` | admin | adminMiddleware() |
| ADM-043 | GET | `/minio/admin/v3/list-access-keys-bulk?listType` | `ListAccessKeysBulk` | admin | adminMiddleware() |
| ADM-044 | GET | `/minio/admin/v3/info-access-key?accessKey` | `InfoAccessKey` | admin | adminMiddleware() |
| ADM-045 | GET | `/minio/admin/v3/info-canned-policy?name` | `InfoCannedPolicy` | admin | adminMiddleware() |
| ADM-046 | GET | `/minio/admin/v3/list-canned-policies?bucket` | `ListBucketPolicies` | admin | adminMiddleware() |
| ADM-047 | GET | `/minio/admin/v3/list-canned-policies  _(query/matcher: (no bucket))_` | `ListCannedPolicies` | admin | adminMiddleware() |
| ADM-048 | GET | `/minio/admin/v3/idp/builtin/policy-entities` | `ListPolicyMappingEntities` | admin | adminMiddleware() |
| ADM-049 | DELETE | `/minio/admin/v3/remove-canned-policy?name` | `RemoveCannedPolicy` | admin | adminMiddleware() |
| ADM-050 | PUT | `/minio/admin/v3/set-user-or-group-policy?policyName&userOrGroup&isGroup` | `SetPolicyForUserOrGroup` | admin | adminMiddleware() |
| ADM-051 | POST | `/minio/admin/v3/idp/builtin/policy/{operation}` | `AttachDetachPolicyBuiltin` | admin | adminMiddleware() |
| ADM-052 | DELETE | `/minio/admin/v3/remove-user?accessKey` | `RemoveUser` | admin | adminMiddleware() |
| ADM-053 | GET | `/minio/admin/v3/list-users?bucket` | `ListBucketUsers` | admin | adminMiddleware() |
| ADM-054 | GET | `/minio/admin/v3/list-users  _(query/matcher: (no bucket))_` | `ListUsers` | admin | adminMiddleware() |
| ADM-055 | GET | `/minio/admin/v3/user-info?accessKey` | `GetUserInfo` | admin | adminMiddleware() |
| ADM-056 | PUT | `/minio/admin/v3/update-group-members` | `UpdateGroupMembers` | admin | adminMiddleware() |
| ADM-057 | GET | `/minio/admin/v3/group?group` | `GetGroup` | admin | adminMiddleware() |
| ADM-058 | GET | `/minio/admin/v3/groups` | `ListGroups` | admin | adminMiddleware() |
| ADM-059 | PUT | `/minio/admin/v3/set-group-status?group&status` | `SetGroupStatus` | admin | adminMiddleware() |
| ADM-060 | GET | `/minio/admin/v3/export-iam` | `ExportIAM` | admin | adminMiddleware(noGZFlag) |
| ADM-061 | PUT | `/minio/admin/v3/import-iam` | `ImportIAM` | admin | adminMiddleware(noGZFlag) |
| ADM-062 | PUT | `/minio/admin/v3/import-iam-v2` | `ImportIAMV2` | admin | adminMiddleware(noGZFlag) |
| ADM-063 | PUT | `/minio/admin/v3/idp-config/{type}/{name}` | `AddIdentityProviderCfg` | admin | adminMiddleware() |
| ADM-064 | POST | `/minio/admin/v3/idp-config/{type}/{name}` | `UpdateIdentityProviderCfg` | admin | adminMiddleware() |
| ADM-065 | GET | `/minio/admin/v3/idp-config/{type}` | `ListIdentityProviderCfg` | admin | adminMiddleware() |
| ADM-066 | GET | `/minio/admin/v3/idp-config/{type}/{name}` | `GetIdentityProviderCfg` | admin | adminMiddleware() |
| ADM-067 | DELETE | `/minio/admin/v3/idp-config/{type}/{name}` | `DeleteIdentityProviderCfg` | admin | adminMiddleware() |
| ADM-068 | PUT | `/minio/admin/v3/idp/ldap/add-service-account` | `AddServiceAccountLDAP` | admin | adminMiddleware() |
| ADM-069 | GET | `/minio/admin/v3/idp/ldap/list-access-keys?userDN&listType` | `ListAccessKeysLDAP` | admin | adminMiddleware() |
| ADM-070 | GET | `/minio/admin/v3/idp/ldap/list-access-keys-bulk?listType` | `ListAccessKeysLDAPBulk` | admin | adminMiddleware() |
| ADM-071 | GET | `/minio/admin/v3/idp/ldap/policy-entities` | `ListLDAPPolicyMappingEntities` | admin | adminMiddleware() |
| ADM-072 | POST | `/minio/admin/v3/idp/ldap/policy/{operation}` | `AttachDetachPolicyLDAP` | admin | adminMiddleware() |
| ADM-073 | GET | `/minio/admin/v3/idp/openid/list-access-keys-bulk?listType` | `ListAccessKeysOpenIDBulk` | admin | adminMiddleware() |
| ADM-074 | GET | `/minio/admin/v3/get-bucket-quota?bucket` | `GetBucketQuotaConfigHandler` | admin | adminMiddleware() |
| ADM-075 | PUT | `/minio/admin/v3/set-bucket-quota?bucket` | `PutBucketQuotaConfigHandler` | admin | adminMiddleware() |
| ADM-076 | GET | `/minio/admin/v3/list-remote-targets?bucket&type` | `ListRemoteTargetsHandler` | admin | adminMiddleware() |
| ADM-077 | PUT | `/minio/admin/v3/set-remote-target?bucket` | `SetRemoteTargetHandler` | admin | adminMiddleware() |
| ADM-078 | DELETE | `/minio/admin/v3/remove-remote-target?bucket&arn` | `RemoveRemoteTargetHandler` | admin | adminMiddleware() |
| ADM-079 | POST | `/minio/admin/v3/replication/diff?bucket` | `ReplicationDiffHandler` | admin | adminMiddleware() |
| ADM-080 | GET | `/minio/admin/v3/replication/mrf?bucket` | `ReplicationMRFHandler` | admin | adminMiddleware() |
| ADM-081 | POST | `/minio/admin/v3/start-job` | `StartBatchJob` | admin | adminMiddleware() |
| ADM-082 | GET | `/minio/admin/v3/list-jobs` | `ListBatchJobs` | admin | adminMiddleware() |
| ADM-083 | GET | `/minio/admin/v3/status-job` | `BatchJobStatus` | admin | adminMiddleware() |
| ADM-084 | GET | `/minio/admin/v3/describe-job` | `DescribeBatchJob` | admin | adminMiddleware() |
| ADM-085 | DELETE | `/minio/admin/v3/cancel-job` | `CancelBatchJob` | admin | adminMiddleware() |
| ADM-086 | GET | `/minio/admin/v3/export-bucket-metadata` | `ExportBucketMetadataHandler` | admin | adminMiddleware() |
| ADM-087 | PUT | `/minio/admin/v3/import-bucket-metadata` | `ImportBucketMetadataHandler` | admin | adminMiddleware() |
| ADM-088 | PUT | `/minio/admin/v3/tier` | `AddTierHandler` | admin | adminMiddleware() |
| ADM-089 | POST | `/minio/admin/v3/tier/{tier}` | `EditTierHandler` | admin | adminMiddleware() |
| ADM-090 | GET | `/minio/admin/v3/tier` | `ListTierHandler` | admin | adminMiddleware() |
| ADM-091 | DELETE | `/minio/admin/v3/tier/{tier}` | `RemoveTierHandler` | admin | adminMiddleware() |
| ADM-092 | GET | `/minio/admin/v3/tier/{tier}` | `VerifyTierHandler` | admin | adminMiddleware() |
| ADM-093 | GET | `/minio/admin/v3/tier-stats` | `TierStatsHandler` | admin | adminMiddleware() |
| ADM-094 | PUT | `/minio/admin/v3/site-replication/add` | `SiteReplicationAdd` | admin | adminMiddleware() |
| ADM-095 | PUT | `/minio/admin/v3/site-replication/remove` | `SiteReplicationRemove` | admin | adminMiddleware() |
| ADM-096 | GET | `/minio/admin/v3/site-replication/info` | `SiteReplicationInfo` | admin | adminMiddleware() |
| ADM-097 | GET | `/minio/admin/v3/site-replication/metainfo` | `SiteReplicationMetaInfo` | admin | adminMiddleware() |
| ADM-098 | GET | `/minio/admin/v3/site-replication/status` | `SiteReplicationStatus` | admin | adminMiddleware() |
| ADM-099 | POST | `/minio/admin/v3/site-replication/devnull` | `SiteReplicationDevNull` | admin | adminMiddleware(noObjLayerFlag) |
| ADM-100 | POST | `/minio/admin/v3/site-replication/netperf` | `SiteReplicationNetPerf` | admin | adminMiddleware(noObjLayerFlag) |
| ADM-101 | PUT | `/minio/admin/v3/site-replication/peer/join` | `SRPeerJoin` | admin | adminMiddleware() |
| ADM-102 | PUT | `/minio/admin/v3/site-replication/peer/bucket-ops?bucket&operation` | `SRPeerBucketOps` | admin | adminMiddleware() |
| ADM-103 | PUT | `/minio/admin/v3/site-replication/peer/iam-item` | `SRPeerReplicateIAMItem` | admin | adminMiddleware() |
| ADM-104 | PUT | `/minio/admin/v3/site-replication/peer/bucket-meta` | `SRPeerReplicateBucketItem` | admin | adminMiddleware() |
| ADM-105 | GET | `/minio/admin/v3/site-replication/peer/idp-settings` | `SRPeerGetIDPSettings` | admin | adminMiddleware() |
| ADM-106 | PUT | `/minio/admin/v3/site-replication/edit` | `SiteReplicationEdit` | admin | adminMiddleware() |
| ADM-107 | PUT | `/minio/admin/v3/site-replication/peer/edit` | `SRPeerEdit` | admin | adminMiddleware() |
| ADM-108 | PUT | `/minio/admin/v3/site-replication/peer/remove` | `SRPeerRemove` | admin | adminMiddleware() |
| ADM-109 | PUT | `/minio/admin/v3/site-replication/resync/op?operation` | `SiteReplicationResyncOp` | admin | adminMiddleware() |
| ADM-110 | PUT | `/minio/admin/v3/site-replication/state/edit` | `SRStateEdit` | admin | adminMiddleware() |
| ADM-111 | GET | `/minio/admin/v3/top/locks` | `TopLocksHandler [gated: `globalIsDistErasure`]` | admin | adminMiddleware() |
| ADM-112 | POST | `/minio/admin/v3/force-unlock?paths` | `ForceUnlockHandler [gated: `globalIsDistErasure`]` | admin | adminMiddleware() |
| ADM-113 | POST | `/minio/admin/v3/speedtest` | `ObjectSpeedTestHandler` | admin | adminMiddleware(noGZFlag) |
| ADM-114 | POST | `/minio/admin/v3/speedtest/object` | `ObjectSpeedTestHandler` | admin | adminMiddleware(noGZFlag) |
| ADM-115 | POST | `/minio/admin/v3/speedtest/drive` | `DriveSpeedtestHandler` | admin | adminMiddleware(noGZFlag) |
| ADM-116 | POST | `/minio/admin/v3/speedtest/net` | `NetperfHandler` | admin | adminMiddleware(noGZFlag) |
| ADM-117 | POST | `/minio/admin/v3/speedtest/site` | `SitePerfHandler` | admin | adminMiddleware(noGZFlag) |
| ADM-118 | POST | `/minio/admin/v3/speedtest/client/devnull` | `ClientDevNull` | admin | adminMiddleware(noGZFlag) |
| ADM-119 | POST | `/minio/admin/v3/speedtest/client/devnull/extratime` | `ClientDevNullExtraTime` | admin | adminMiddleware(noGZFlag) |
| ADM-120 | GET | `/minio/admin/v3/trace` | `TraceHandler` | admin | adminMiddleware(noObjLayerFlag) |
| ADM-121 | GET | `/minio/admin/v3/log` | `ConsoleLogHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-122 | POST | `/minio/admin/v3/kms/status` | `KMSStatusHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-123 | POST | `/minio/admin/v3/kms/key/create?key-id` | `KMSCreateKeyHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-124 | GET | `/minio/admin/v3/kms/key/status` | `KMSKeyStatusHandler` | admin | adminMiddleware(traceAllFlag) |
| ADM-125 | GET | `/minio/admin/v3/obdinfo  _(query/matcher: (back-compat alias))_` | `HealthInfoHandler` | admin | adminMiddleware() |
| ADM-126 | GET | `/minio/admin/v3/healthinfo` | `HealthInfoHandler` | admin | adminMiddleware() |
| ADM-127 | POST | `/minio/admin/v3/revoke-tokens/{userProvider}` | `RevokeTokens` | admin | adminMiddleware() |

## Admin router -- catch-all handlers

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| ADM-CATCH-001 | * | `/minio/admin/v3*?unmatched path` | `errorResponseHandler` | admin | httpTraceAll (catch-all, no adminMiddleware) |
| ADM-CATCH-002 | * | `/minio/admin/v3*?unmatched method` | `methodNotAllowedHandler("Admin")` | admin | httpTraceAll (catch-all, no adminMiddleware) |

## STS router (`cmd/sts-handlers.go: registerSTSRouter`) -- mounted at root `/`, disambiguated by MatcherFunc/Queries, not by path

> No `s3APIMiddleware`/`adminMiddleware` equivalent exists for STS; every route is `httpTraceAll(sts.<Handler>)` directly.
> `AssumeRole` is the only route whose *router-level MatcherFunc* checks for a MinIO SigV4 `Authorization` header; the other 6 issuance routes accept any POST matching their form fields and perform authentication *inside* the handler (LDAP bind, JWT/OIDC validation, mTLS client-cert verification, or an external auth plugin) -- by design, since STS is the pre-auth credential-issuance surface.

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| STS-001 | POST | `/?MatcherFunc: ctype=x-www-form-urlencoded* AND Authorization=AWS4-HMAC-SHA256* AND no query string` | `AssumeRole` | sts | httpTraceAll() -- only STS route requiring a MinIO SigV4 Authorization header at the router match; checkAssumeRoleAuth() called inside handler body |
| STS-002 | POST | `/?MatcherFunc: ctype=x-www-form-urlencoded* AND no query string (no auth-header check)` | `AssumeRoleWithSSO` | sts | httpTraceAll() -- dispatches internally to LDAPIdentity/ClientGrants/WebIdentity by Action form value |
| STS-003 | POST | `/?Action=AssumeRoleWithClientGrants&Version=2011-06-15&Token=<jwt>` | `AssumeRoleWithClientGrants` | sts | httpTraceAll() |
| STS-004 | POST | `/?Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=<jwt>` | `AssumeRoleWithWebIdentity` | sts | httpTraceAll() |
| STS-005 | POST | `/?Action=AssumeRoleWithLDAPIdentity&Version=2011-06-15&LDAPUsername&LDAPPassword` | `AssumeRoleWithLDAPIdentity` | sts | httpTraceAll() |
| STS-006 | POST | `/?Action=AssumeRoleWithCertificate&Version=2011-06-15 (mTLS)` | `AssumeRoleWithCertificate` | sts | httpTraceAll() |
| STS-007 | POST | `/?Action=AssumeRoleWithCustomToken&Version=2011-06-15` | `AssumeRoleWithCustomToken` | sts | httpTraceAll() |

## KMS router (`cmd/kms-router.go`) -- prefix `/minio/kms/v1`

> All paths relative to `/minio/kms/v1` (= `kmsPathPrefix` `/minio/kms` + `/v1`).
> **No `adminMiddleware` (or any equivalent) wraps any KMS route** -- registration is `gz(httpTraceAll(kmsAPI.XxxHandler))` only.
> Cross-reference: `KMSStatusHandler`, `KMSCreateKeyHandler`, `KMSKeyStatusHandler` are also reachable under the admin router (`ADM-122..124`, `/minio/admin/v3/kms/...`) wrapped in `adminMiddleware(traceAllFlag)` -- the same three operations exist twice, gated differently at the router layer.

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| KMS-001 | GET | `/minio/kms/v1/status` | `KMSStatusHandler` | kms | gz(httpTraceAll()) -- NO adminMiddleware/auth-gate wrapper visible |
| KMS-002 | GET | `/minio/kms/v1/metrics` | `KMSMetricsHandler` | kms | gz(httpTraceAll()) -- NO adminMiddleware/auth-gate wrapper visible |
| KMS-003 | GET | `/minio/kms/v1/apis` | `KMSAPIsHandler` | kms | gz(httpTraceAll()) -- NO adminMiddleware/auth-gate wrapper visible |
| KMS-004 | GET | `/minio/kms/v1/version` | `KMSVersionHandler` | kms | gz(httpTraceAll()) -- NO adminMiddleware/auth-gate wrapper visible |
| KMS-005 | POST | `/minio/kms/v1/key/create?key-id` | `KMSCreateKeyHandler` | kms | gz(httpTraceAll()) -- NO adminMiddleware/auth-gate wrapper visible |
| KMS-006 | GET | `/minio/kms/v1/key/list?pattern` | `KMSListKeysHandler` | kms | gz(httpTraceAll()) -- NO adminMiddleware/auth-gate wrapper visible |
| KMS-007 | GET | `/minio/kms/v1/key/status` | `KMSKeyStatusHandler` | kms | gz(httpTraceAll()) -- NO adminMiddleware/auth-gate wrapper visible |

## KMS router -- catch-all handlers

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| KMS-CATCH-001 | * | `/minio/kms/v1*?unmatched path` | `errorResponseHandler` | kms | httpTraceAll (catch-all) |
| KMS-CATCH-002 | * | `/minio/kms/v1*?unmatched method` | `methodNotAllowedHandler("KMS")` | kms | httpTraceAll (catch-all) |

## Metrics router (`cmd/metrics-router.go`) -- prefix `/minio`

> `authType := env MINIO_PROMETHEUS_AUTH_TYPE` (default `"jwt"`); `auth := AuthMiddleware` unless `authType=="public"`, in which case `auth := NoAuthMiddleware` (a bare passthrough, `metrics.go:528`) for ALL 6 routes below -- operator-configurable anonymous metrics.
> `AuthMiddleware` (`metrics.go:533`) validates a bearer/JWT token and then calls `globalIAMSys.IsAllowed(...policy.PrometheusAdminAction...)`.

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| MET-001 | GET(any, via Handle) | `/minio/prometheus/metrics` | `metricsHandler()` | metrics | auth(...) = AuthMiddleware [default JWT+IAM PrometheusAdminAction] / NoAuthMiddleware if MINIO_PROMETHEUS_AUTH_TYPE=public |
| MET-002 | GET(any, via Handle) | `/minio/v2/metrics/cluster` | `metricsServerHandler()` | metrics | auth(...) = AuthMiddleware [default] / NoAuthMiddleware if public |
| MET-003 | GET(any, via Handle) | `/minio/v2/metrics/bucket` | `metricsBucketHandler()` | metrics | auth(...) = AuthMiddleware [default] / NoAuthMiddleware if public |
| MET-004 | GET(any, via Handle) | `/minio/v2/metrics/node` | `metricsNodeHandler()` | metrics | auth(...) = AuthMiddleware [default] / NoAuthMiddleware if public |
| MET-005 | GET(any, via Handle) | `/minio/v2/metrics/resource` | `metricsResourceHandler()` | metrics | auth(...) = AuthMiddleware [default] / NoAuthMiddleware if public |
| MET-006 | GET | `/minio/metrics/v3{pathComps:.*}?optional ?list` | `metricsV3Server (newMetricsV3Server(auth))` | metrics | auth(...) = AuthMiddleware [default] / NoAuthMiddleware if public |

## Healthcheck router (`cmd/healthcheck-router.go`) -- prefix `/minio/health`

| entry_id | method | path | handler | router | auth wrapper at registration |
|---|---|---|---|---|---|
| HC-001 | GET | `/minio/health/cluster` | `ClusterCheckHandler` | health | httpTraceAll() -- no auth wrapper (by design: probe endpoint) |
| HC-002 | HEAD | `/minio/health/cluster` | `ClusterCheckHandler` | health | httpTraceAll() -- no auth wrapper (by design: probe endpoint) |
| HC-003 | GET | `/minio/health/cluster/read` | `ClusterReadCheckHandler` | health | httpTraceAll() -- no auth wrapper (by design: probe endpoint) |
| HC-004 | HEAD | `/minio/health/cluster/read` | `ClusterReadCheckHandler` | health | httpTraceAll() -- no auth wrapper (by design: probe endpoint) |
| HC-005 | GET | `/minio/health/live` | `LivenessCheckHandler` | health | httpTraceAll() -- no auth wrapper (by design: probe endpoint) |
| HC-006 | HEAD | `/minio/health/live` | `LivenessCheckHandler` | health | httpTraceAll() -- no auth wrapper (by design: probe endpoint) |
| HC-007 | GET | `/minio/health/ready` | `ReadinessCheckHandler` | health | httpTraceAll() -- no auth wrapper (by design: probe endpoint) |
| HC-008 | HEAD | `/minio/health/ready` | `ReadinessCheckHandler` | health | httpTraceAll() -- no auth wrapper (by design: probe endpoint) |

## Totals

| router | route count (incl. catch-alls) |
|---|---|
| s3 | 95 |
| admin | 129 |
| sts | 7 |
| kms | 9 |
| metrics | 6 |
| health | 8 |
| **total** | **254** |

## Candidate unauth/anonymous surface -- routes with NO route-scoped auth-gate wrapper visible at registration

Criterion: a router-specific auth-oriented middleware equivalent to `s3APIMiddleware`/`adminMiddleware`/`AuthMiddleware` is absent from the registration call; the handler is invoked through tracing/gzip helpers only. (Every route in every router still passes through the *global* `setAuthMiddleware`, which only validates that a supported auth-type/date header is present -- it performs no authorization -- so that alone is not used as a disqualifying signal below; S3 and Admin routes are excluded from this list precisely because they DO carry a route-specific wrapper, `s3APIMiddleware`/`adminMiddleware`, even though that wrapper itself does no authz check either.)

1. **KMS router -- all 7 routes** (`KMS-001`..`KMS-007`, `/minio/kms/v1/*`): registered as `gz(httpTraceAll(kmsAPI.XxxHandler))` with no `adminMiddleware`-equivalent wrapper at all. Three of these operations (`status`, `key/create`, `key/status`) are duplicated under the admin router *with* `adminMiddleware(traceAllFlag)` -- an interface-sibling wrapper-parity gap worth checking inside the handler bodies.
2. **STS router -- 6 of 7 issuance routes** (`STS-002`..`STS-007`, all mounted at root `/`): `AssumeRoleWithSSO`/`ClientGrants`/`WebIdentity`/`LDAPIdentity`/`Certificate`/`CustomToken` have no MinIO-native signature check at the mux MatcherFunc (only `AssumeRole`, `STS-001`, requires a SigV4 header at match time). This is expected by design -- STS is the pre-auth credential-issuance surface, authenticated instead against an external IdP/LDAP/cert/plugin inside the handler body -- but it is the literal 'no wrapper at registration' surface.
3. **Healthcheck router -- all 8 routes** (`HC-001`..`HC-008`, `/minio/health/*`): `httpTraceAll()` only, by design (liveness/readiness probes must be reachable pre-auth).
4. **Metrics router -- all 6 routes, conditionally**: default wrapper is `AuthMiddleware` (real IAM check), but every route becomes `NoAuthMiddleware` (bare passthrough) if the operator sets `MINIO_PROMETHEUS_AUTH_TYPE=public` -- an operator-flippable anonymous-surface switch, not a code-level gap.

_Note: S3 (`S3-*`) and Admin (`ADM-*`) routes are wrapped in `s3APIMiddleware`/`adminMiddleware` respectively at registration, so they are excluded from the list above by this manifest's registration-only criterion. However, neither wrapper performs an authorization check itself (see global-middleware section) -- actual permission enforcement for every S3/Admin route happens inside the handler body and was intentionally NOT audited here per scope. That handler-body authz path is the natural next hop for a deeper hunt, not a finding of this manifest._
