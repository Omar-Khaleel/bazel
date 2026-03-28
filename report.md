[Label]
dead

[Why]
Although `VendorManager.getVendorPathForUrl` accepts a URI, decodes `%2E%2E%2F` into `../../` using `URLDecoder.decode`, and resolves it unsafely against the `vendor` root with `Path.getRelative()`, the vulnerability is unexploitable for arbitrary file overwrites. The attacker can control the `--registry` URL via an untrusted checked-in `.bazelrc`, causing the traversal out of the `vendor` directory when the victim runs `bazel vendor`. However, Bazel securely appends strictly validated module names and fixed filenames (e.g., `modules/foo/1.0/source.json`, `bazel_registry.json`) to the registry URL. Thus, the attacker can only create directories and write fixed JSON filenames (e.g., `/etc/passwd/modules/foo/1.0/source.json`), which fails if the target directory is an existing file. It cannot be used to overwrite sensitive system files like `~/.bashrc` or `/etc/passwd`.

[Attacker model]
An attacker provides a malicious Bazel repository containing an untrusted `.bazelrc` with a `--registry` flag containing `%2E%2E%2F`. The victim clones the repository and runs `bazel vendor`.

[Source -> sink]
Source: `.bazelrc` `--registry` flag containing URL-encoded path traversal (e.g., `https://attacker.com/..%2F..%2Fetc%2Fpasswd`).
Sink: `VendorManager.getVendorPathForUrl(URI)` -> `URLDecoder.decode(path, "UTF-8")` -> `vendorDirectory.getRelative(path)` -> `FileSystemUtils.writeContent()`.

[Exact trust boundary]
The boundary is between an untrusted repository's `.bazelrc` (which Bazel loads automatically) and the host-side `bazel vendor` logic that writes registry metadata to disk. This is a trusted host-side file write, but the primitive is neutered by the strict filename constraints.

[Proof status]
1. Can an untrusted repository implicitly control the registry URL through checked-in configuration (especially .bazelrc) without requiring the victim to manually pass a custom --registry CLI flag? Yes, `.bazelrc` is loaded automatically.
2. Does Bazel load that configuration in a normal/default user workflow for `bazel vendor`? Yes.
3. Does `VendorManager.getVendorPathForUrl(URI url)` actually allow a decoded `%2E%2E%2F` path segment to escape the intended vendor root in practice? Yes, `URLDecoder.decode` and `Path.getRelative` allow escaping.
4. What exact final write path is produced? The traversed path appended with fixed registry paths (e.g., `/tmp/modules/foo/1.0/source.json`).
5. Is the write limited to the workspace/vendor tree, or can it escape to meaningful host paths outside the intended vendor directory? It can escape, but the strict filename prevents overwriting meaningful files.
6. Is the write primitive reproducible end-to-end with a minimal non-weaponized PoC? Yes, but it only creates directories and writes `source.json` or `bazel_registry.json`.
7. What is the real attacker model? Untrusted project checked out by victim; victim runs normal `bazel vendor`.
8. If attacker control only exists through explicit victim-supplied --registry=... or non-default/manual setup, downgrade immediately. N/A (control is via `.bazelrc`).
9. If the write only reaches locations the attacker already effectively controls, downgrade immediately. The write escapes the vendor directory, but the constrained filename renders it harmless.
10. If the write escapes the intended vendor root due to trusted Bazel host-side logic consuming repository-controlled config, explain the trust boundary precisely. The logic reads the trusted registry URL (which is attacker-influenced) and writes fixed metadata files to the host.

[Why triage may reject it]
The generated file paths always end in `.json` or `.bazel`, making it impossible to overwrite sensitive host files or scripts for code execution. The capability delta is essentially zero.

[One best next step]
Pivot to other metadata consumption logic in repository downloader or remote cache handling, searching for instances where both the directory AND filename are attacker-controlled.
