# How to audit a host

The `audit` resource assesses inventories against Vulners intelligence. Pick the method that
matches what you can collect from the host.

## Audit a Linux host by installed packages

Collect the installed packages in the distro's native format and pass them to
`audit.linux_audit`:

=== "Sync"

    ```python
    from vulners import Vulners

    # dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'   (Debian/Ubuntu)
    # rpm -qa                                                        (RHEL/Alma/Rocky)
    # apk info -v                                                    (Alpine)
    packages = [
        "openssl 1.1.1d-0+deb10u3 amd64",
        "bash 5.0-4 amd64",
    ]

    with Vulners() as v:
        report = v.audit.linux_audit(
            os_name="debian",
            os_version="10",
            packages=packages,
        )
        print(report)
    ```

=== "Async"

    ```python
    from vulners import AsyncVulners

    # dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'   (Debian/Ubuntu)
    # rpm -qa                                                        (RHEL/Alma/Rocky)
    # apk info -v                                                    (Alpine)
    packages = [
        "openssl 1.1.1d-0+deb10u3 amd64",
        "bash 5.0-4 amd64",
    ]

    async with AsyncVulners() as v:
        report = await v.audit.linux_audit(
            os_name="debian",
            os_version="10",
            packages=packages,
        )
        print(report)
    ```

`linux_audit` accepts up to 2500 packages and several toggles — `os_arch`,
`include_unofficial`, `include_candidates`, `include_any_version`, `cvelist_metrics`,
`fields` — see the [reference](../reference/resources.md#vulners._resources._sync.audit.Audit).
Each issue carries the package, its `fixedVersion`/`fixedPackage` and the matching
`applicableAdvisories`; the result also reports the `appliedOptions` that took effect and any
`warnings` (for example an unsupported enrichment option).

## Audit a host by CPE

If you have CPE identifiers for the host's software (and optionally its OS, application and
hardware), use `audit.host`:

=== "Sync"

    ```python
    with Vulners() as v:
        report = v.audit.host(
            ["cpe:2.3:a:openssl:openssl:1.0.1"],
            operating_system="cpe:2.3:o:canonical:ubuntu_linux:22.04",
            match="partial",           # or "full"
        )
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        report = await v.audit.host(
            ["cpe:2.3:a:openssl:openssl:1.0.1"],
            operating_system="cpe:2.3:o:canonical:ubuntu_linux:22.04",
            match="partial",           # or "full"
        )
    ```

For a flat software list with no OS/hardware context, use `audit.software` instead.

## Audit a Windows host by installed KBs

=== "Sync"

    ```python
    with Vulners() as v:
        report = v.audit.win_audit(
            os="Windows Server 2012 R2",
            os_version="10.0.19045",
            kb_list=["KB2918614", "KB2918616"],
            software=[{"software": "Google Chrome", "version": "120.0.6099.130"}],
        )
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        report = await v.audit.win_audit(
            os="Windows Server 2012 R2",
            os_version="10.0.19045",
            kb_list=["KB2918614", "KB2918616"],
            software=[{"software": "Google Chrome", "version": "120.0.6099.130"}],
        )
    ```

If you only have the KB list, `audit.kb_audit` reports the missing updates directly. It uses
`/api/v4/audit/kb` and returns one finding per missing update — each with the fixing package
(`fixedPackage`) and the KBs that update supersedes:

=== "Sync"

    ```python
    with Vulners() as v:
        report = v.audit.kb_audit(
            "Windows Server 2012 R2", ["KB2918614", "KB2918616"]
        )
        for item in report["items"]:
            print(item["fixedPackage"], "->", [a["id"] for a in item["advisories"]])
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        report = await v.audit.kb_audit(
            "Windows Server 2012 R2", ["KB2918614", "KB2918616"]
        )
    ```

!!! note "v3 vs v4"
    The legacy v3 endpoint returned a flat CVE list (`kbLatest`/`kbMissed`/`cvelist`). It is
    deprecated but still available as `audit.kb_audit_v3(os=..., kb_list=[...])`.

## Audit an SBOM

Have an SPDX or CycloneDX file? Upload it directly:

=== "Sync"

    ```python
    with Vulners() as v:
        report = v.audit.sbom_audit("sbom.cdx.json")
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        report = await v.audit.sbom_audit("sbom.cdx.json")
    ```

## Audit free-form software names

When you only have imprecise product strings (no CPE), `audit.smart` resolves each string to
a CPE/PURL heuristically and returns the affecting vulnerabilities:

=== "Sync"

    ```python
    with Vulners() as v:
        results = v.audit.smart(["Apache HTTP Server 2.4.49", "nginx 1.18.0"])
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        results = await v.audit.smart(["Apache HTTP Server 2.4.49", "nginx 1.18.0"])
    ```

!!! warning "Billing"
    `smart` is a preview endpoint and is **billed per submitted string** (1–500 entries, each
    ≤ 512 characters). Keep the batch to what you need.

## Enrich findings with CVSS, EPSS and exploitation

The audit endpoints can attach severity and exploitation intelligence to each finding:

- **`software` / `host`**: pass `cvelist_metrics=True` to add per-CVE `cvelist` and
  `cvelistMetrics` (CVSS/EPSS per CVE) to every finding; each result already carries the
  `fixed_version` that resolves it. The applied projection is echoed in the
  `X-Vulners-Applied-Options` response header (read it via `with_raw_response`).
- **`smart`**: pass `fields=[...]` to project which fields each vulnerability carries — for
  example `["metrics", "exploitation", "cvelist", "cvelistMetrics"]`. An unknown field name is
  rejected with a `400`.
- **`linux_audit` / `library_audit`**: pass `fields=["metrics"]` (these endpoints support
  `metrics` and `cvelistMetrics`); the result reports which `appliedOptions` took effect and
  any `warnings` for unsupported ones.
- **`sbom_audit`**: pass `cvelist_metrics=True` (sent as a query option, since the body carries
  the uploaded file); the result carries `appliedOptions` and `warnings` alongside the data.

=== "Sync"

    ```python
    with Vulners() as v:
        # per-CVE CVSS/EPSS on a software audit
        report = v.audit.software(["cpe:2.3:a:google:chrome:100.0.4896.60"], cvelist_metrics=True)

        # project exploitation + metrics onto smart results
        results = v.audit.smart(
            ["Google Chrome 100.0"], fields=["metrics", "exploitation", "cvelistMetrics"]
        )
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        report = await v.audit.software(
            ["cpe:2.3:a:google:chrome:100.0.4896.60"], cvelist_metrics=True
        )
        results = await v.audit.smart(
            ["Google Chrome 100.0"], fields=["metrics", "exploitation", "cvelistMetrics"]
        )
    ```
