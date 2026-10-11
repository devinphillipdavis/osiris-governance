# OSIRIS Cloud Run Security Baseline & Workload Confinement

**Classification:** Infrastructure Security Baseline  
**Document ID:** `OSIRIS-CLOUD-RUN-SEC-V1`  
**Target Platform:** Google Cloud Run (Fully Managed Serverless Container Platform)  
**Governing Standard:** OSIRIS Least-Privilege & Verified Confinement Policy  
**Last Updated:** 2026-09-27T11:24:00Z  

---

## 1. Cloud Run Execution Model & Architectural Boundaries

Google Cloud Run executes container instances inside a managed runtime environment built upon **gVisor**, an application kernel written in Go that intercepts system calls and provides a strong virtualization boundary between the container payload and the host Linux kernel.

### Critical De-Scoping: Correcting Technical Misconceptions
To maintain architectural integrity, the following unsupported assertions are formally purged from OSIRIS specifications:
1. **No Application-Level Seccomp Probing:** Cloud Run does not provide a workload-level contract allowing applications to inspect, configure, or enforce custom Linux `seccomp` BPF filters. Any `/proc` or system call probing executed from within a container reflects gVisor's virtualized syscall table, not direct host kernel confinement.
2. **No Docker Capability Dropping (`CAP_DROP=ALL`):** Managed Cloud Run does not expose Docker-style capability flags (`--cap-drop`). Privilege boundaries are enforced by the gVisor sandbox and Google Cloud IAM, not Linux capability masks.
3. **`/tmp` Filesystem Reality:** In Cloud Run, `/tmp` is implemented as an in-memory `tmpfs` volume shared across threads within an instance. **Writing to `/tmp` is standard documented platform behavior and does NOT indicate a host filesystem escape.** Write-confinement policies must focus on application-level file handlers and verifying that root filesystems remain immutable where applicable.

---

## 2. Service Account Identity & IAM Separation

A common vulnerability in cloud deployments is granting the CI/CD deployer service account broad administrative privileges (`roles/run.admin` or `roles/editor`). OSIRIS strictly enforces identity separation:

```
┌──────────────────────────────────────┐          ┌──────────────────────────────────────┐
│       DEPLOYER SERVICE ACCOUNT       │          │       RUNTIME SERVICE ACCOUNT        │
│   (Cloud Build / Deployment Runner)  │          │    (Cloud Run Container Instance)    │
├──────────────────────────────────────┤          ├──────────────────────────────────────┤
│ Roles:                               │          │ Roles:                               │
│ - roles/run.developer (service only) │ actAs    │ - roles/secretmanager.secretAccessor │
│ - roles/iam.serviceAccountUser       │─────────▶│   (only on declared secret IDs)      │
│   (on Runtime SA ONLY)               │          │ - roles/logging.logWriter            │
│ Strictly NO Project-Wide Admin Roles │          │ Strictly NO Deployment / Admin Roles │
└──────────────────────────────────────┘          └──────────────────────────────────────┘
```

### Configuration Rules
1. **Dedicated Runtime Service Account:** The Cloud Run service `dnalang` must run under its own dedicated identity (e.g., `sa-osiris-runtime@living-language-model.iam.gserviceaccount.com`). The default Compute Engine service account (`<project-number>-compute@developer.gserviceaccount.com`) must never be used.
2. **Narrow `actAs` Binding:** The Cloud Build service account is granted `roles/iam.serviceAccountUser` *exclusively* on `sa-osiris-runtime`. Granting `roles/iam.serviceAccountUser` at the project level is strictly prohibited.
3. **No Credential Export:** The runtime service account relies solely on Google Cloud Application Default Credentials (ADC) provided by the metadata server. No private service account key files (`.json`) may ever be created or baked into container images.

---

## 3. Secret Management & Injection Baseline

Storing secrets in plain environment variables poses a severe risk of accidental logging, exposure in environment dumps, or leakage in process inspection interfaces.

### Enforcement Standards
1. **Google Cloud Secret Manager Integration:** All production secrets (database credentials, API keys) must be managed in Google Cloud Secret Manager.
2. **Mounting via Cloud Run Configuration:** Secrets must be referenced natively via Cloud Run service parameters:
   ```yaml
   spec:
     containers:
       - image: europe-west1-docker.pkg.dev/living-language-model/osiris/dnalang@sha256:...
         env:
           - name: GEMINI_API_KEY
             valueFrom:
               secretKeyRef:
                 name: gemini-api-key
                 key: latest
   ```
3. **Process-Level Redaction:** The application must implement structured log redaction (`osiris/security/credentials.py`) ensuring that if an exception occurs during secret retrieval, raw secret bytes and token suffixes are stripped prior to log emission.

---

## 4. Ingress, Network Boundaries & Digest Pinning

### Network Ingress Rules
- **Staging / Internal Workloads:** Services must be deployed with ingress restricted to internal traffic:
  ```bash
  gcloud run services update dnalang \
    --ingress internal \
    --no-allow-unauthenticated \
    --region europe-west1 \
    --project living-language-model
  ```
- **Public Endpoints:** If public access is mandated, it must terminate at Cloud Armor and an HTTPS Cloud Load Balancer with rate limiting, WAF rules, and DDoS protection active. Direct unauthenticated internet exposure of raw Cloud Run URLs is prohibited for production workloads.

### Immutable Digest Pinning
- **Tagging vs. Digest:** Container images must never be deployed by tag (e.g., `:latest` or `:commit-8b3f047`).
- **Deployment Manifest Requirement:** The deployment configuration must explicitly pin the SHA-256 digest:
  ```text
  europe-west1-docker.pkg.dev/living-language-model/osiris/dnalang@sha256:d8c5...
  ```
- **Binary Authorization:** In production environments, Google Cloud Binary Authorization must be enabled to cryptographically verify attestations before container launch.

---

## 5. Security Verification Checklist for Cloud Run Deployment

| Item | Requirement | Verification Command / Check |
|---|---|---|
| **Identity** | Service runs as dedicated runtime SA | `gcloud run services describe dnalang --format="value(spec.template.spec.serviceAccountName)"` |
| **Ingress** | Ingress restricted to internal / LB | `gcloud run services describe dnalang --format="value(metadata.annotations['run.googleapis.com/ingress'])"` |
| **Authentication** | Unauthenticated requests blocked | `gcloud run services get-iam-policy dnalang` (Verify `allUsers` does NOT have `roles/run.invoker`) |
| **Secrets** | Zero plaintext secrets in env vars | `gcloud run services describe dnalang --format="value(spec.template.spec.containers[0].env)"` |
| **Image** | Pinned by cryptographic digest | Ensure image reference contains `@sha256:` |
