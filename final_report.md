As requested, I pivoted to investigate metadata and filepath consumption bugs where **BOTH** the target directory AND the written filename/artifact identity are attacker-influenced, prioritizing repository downloader, repository cache, mirror URLs, and cache materialization.

I have thoroughly audited the associated code (`DownloadManager`, `HttpDownloader`, `UrlRewriter`, `DownloadCache`, `LocalRepoContentsCache`, `IndexRegistry`, `VendorManager`, and Starlark `repository_ctx` fetching functions). I aggressively killed findings that amount to "local-only self-attack", "intended build-script execution", or "harmless traversal".

Here are the results.

### Killed Leads (Dead)

1. **`VendorManager.getVendorPathForUrl` Path Escape**
   * **Why dead:** `URLDecoder.decode` and `Path.getRelative` allow escaping the `vendorDirectory` if a registry URL contains `%2E%2E%2F`. However, the filenames are rigidly fixed by `IndexRegistry.java` (e.g., `modules/foo/1.0/source.json`), so an attacker cannot write to an arbitrary target like `/etc/passwd`.
2. **`DownloadCache` Key Confusion via `canonicalId`**
   * **Why dead:** `DownloadManager.getBytesFromCache` ignores `canonicalId`, allowing cache retrieval by SHA256 alone. However, if the SHA256 matches, the file contents are cryptographically identical, so there is no poisoning impact.
3. **Lockfile (`MODULE.bazel.lock`) Repo Injection**
   * **Why dead:** An attacker can modify the lockfile's `generatedRepoSpecs` to bypass extension validation (injecting malicious URLs with correct checksums), but this requires submitting a PR with the modified lockfile to the victim's repo. Modifying checked-in repo state to achieve execution is a known local-only self-attack ("user builds untrusted code").
4. **`archive_override` / `patchCmds` Execution**
   * **Why dead:** These directives are strictly restricted to the root module. An untrusted transitive dependency cannot use them to execute commands on the host.
5. **Archive Symlink / `renameFiles` Traversal**
   * **Why dead:** `StripPrefixedPath.maybeDeprefix` safely rebases absolute and relative symlinks inside the extraction root. `Path.startsWith` validation in `ZipDecompressor` and `CompressedTarFunction` cleanly blocks any `renameFiles` payload attempting to escape the destination directory.

---

### Top 10 Files/Classes to Inspect Next

Since the repository fetching and caching boundaries are robust against directory traversal and cache poisoning, the next best audit surfaces are the **host-side integration points** where generated repository artifacts or downloaded manifests interact with Bazel's trusted execution orchestration (e.g., action execution, runfiles trees, or toolchain resolution).

1. `src/main/java/com/google/devtools/build/lib/analysis/Runfiles.java` (Runfiles manifest parsing and symlink forest generation)
2. `src/main/java/com/google/devtools/build/lib/analysis/RunfilesTreeUpdater.java` (Host-side materialization of runfiles)
3. `src/main/java/com/google/devtools/build/lib/skyframe/ActionExecutionFunction.java` (Action execution orchestration, especially input/output path resolution)
4. `src/main/java/com/google/devtools/build/lib/exec/local/LocalSpawnRunner.java` (Local execution of actions, looking for confused deputy in path selection)
5. `src/main/java/com/google/devtools/build/lib/skyframe/TreeArtifactValue.java` (Tree artifacts and dynamic output discovery)
6. `src/main/java/com/google/devtools/build/lib/vfs/OutputService.java` / `LocalOutputService.java` (Output materialization, especially with Remote Execution enabled)
7. `src/main/java/com/google/devtools/build/lib/remote/GrpcRemoteDownloader.java` (Remote downloader logic, specifically how it handles `canonical_id` and credentials for non-file URLs)
8. `src/main/java/com/google/devtools/build/lib/remote/RemoteActionInputFetcher.java` (Fetching outputs from the remote cache to the local host)
9. `src/main/java/com/google/devtools/build/lib/rules/cpp/CcToolchainProvider.java` (Toolchain metadata consumption from untrusted repos)
10. `src/main/java/com/google/devtools/build/lib/analysis/starlark/StarlarkActionFactory.java` (Starlark `ctx.actions.run` parameter validation and path escaping)

---

### Best Fresh Leads (Promising Audit Surfaces)

Because no strong, immediate bypasses were found in the downloader or cache, these leads represent the most likely places a confused deputy or metadata consumption bug exists.

#### Lead 1: Runfiles Symlink Forest Traversal
**[Label]** promising
**[Why]** Bazel materializes a symlink forest for `runfiles` before executing binaries or tests. If an attacker-controlled repository can define a target name or `runfiles` entry that resolves to `../` or an absolute path, the `RunfilesTreeUpdater` might create arbitrary symlinks on the host.
**[Attacker model]** Untrusted repository defines a `java_binary` or `sh_test` with maliciously crafted `data` dependencies or `runfiles` metadata. Victim builds or tests the target.
**[Source -> sink]** Starlark `DefaultInfo(runfiles=...)` -> `Runfiles.java` -> `RunfilesTreeUpdater.updateRunfilesTree()`.
**[Exact trust boundary]** Untrusted `BUILD` file defining runfiles paths -> Trusted host `RunfilesTreeUpdater` executing filesystem symlink operations.
**[Why triage may reject it]** Triage may claim `BUILD` files are reviewed, but `runfiles` paths are often generated dynamically by macros, making it easier to hide traversal.
**[One best next step]** Audit `Runfiles.java` and `RunfilesTreeUpdater.java` to see if `PathFragment.getRelative` is used unsafely on runfiles paths without a `startsWith` boundary check.

#### Lead 2: Remote Cache Materialization Path Escaping
**[Label]** promising
**[Why]** When Bazel uses Remote Execution (`--remote_executor`), it downloads output artifacts (like TreeArtifacts) from the remote cache to the local output base. If the remote cache metadata (which the attacker might influence by sharing a cache hit) specifies an output path with directory traversal, the local fetcher might write outside the output base.
**[Attacker model]** Attacker and victim share a remote cache. Attacker uploads a malicious Action Cache entry where an output file's path contains `../`. Victim builds the same target and fetches the poisoned output.
**[Source -> sink]** Remote Execution API (Action Cache) -> `RemoteActionInputFetcher.downloadFile()` -> `FileSystemUtils.writeContent()`.
**[Exact trust boundary]** Untrusted/shared Remote Cache metadata -> Trusted local host writing action outputs.
**[Why triage may reject it]** Requires a shared remote cache without strict authorization, or a vulnerability in the remote cache server's path validation.
**[One best next step]** Inspect `RemoteActionInputFetcher.java` and `RemoteExecutionCache.java` for validation of `Action` output paths before materializing them locally.

#### Lead 3: TreeArtifact Metadata Consumption
**[Label]** promising
**[Why]** TreeArtifacts (directory outputs) allow actions to generate unknown files at runtime. If an action running on a Remote Execution worker generates a TreeArtifact containing symlinks or traversals, the local host fetching the TreeArtifact might blindly reconstruct the directory structure.
**[Attacker model]** Attacker creates a rule outputting a TreeArtifact and shares the remote cache. The TreeArtifact contains paths like `../../etc/passwd`. Victim fetches the cache hit.
**[Source -> sink]** Remote Execution API (Tree metadata) -> `TreeArtifactValue.java` -> `OutputService.java`.
**[Exact trust boundary]** Untrusted remote worker executing the action -> Trusted local host materializing the directory.
**[Why triage may reject it]** Depends heavily on the exact implementation of TreeArtifact fetching.
**[One best next step]** Audit how Bazel expands TreeArtifacts fetched from a remote cache in `ActionExecutionFunction.java`.

#### Lead 4: Starlark `ctx.actions.declare_file` Path Traversal
**[Label]** weak
**[Why]** If a Starlark rule can declare an output file with `../` in its name, it might force Bazel to write action outputs outside the action's sandboxed `execroot`.
**[Attacker model]** Untrusted repository defines a macro that calls `ctx.actions.declare_file("../../../pwn")`. Victim builds the target.
**[Source -> sink]** `ctx.actions.declare_file()` -> `StarlarkActionFactory.java` -> `ArtifactFactory`.
**[Exact trust boundary]** Untrusted Starlark rule definition -> Trusted host output path allocation.
**[Why triage may reject it]** Bazel's `Label` and `Artifact` validation is typically very strict about `../`.
**[One best next step]** Check `StarlarkActionFactory.declareFile` for `PathFragment` validation.

#### Lead 5: GrpcRemoteDownloader Credentials Leak via Scheme Confusion
**[Label]** weak
**[Why]** `GrpcRemoteDownloader` checks if `anyMatch(url -> url.getScheme().equals("file"))` to avoid sending `file://` URLs to the remote server. However, if an attacker uses `jar:file://`, the scheme is `jar`, bypassing the check, and the remote execution server is asked to fetch it.
**[Attacker model]** Attacker controls `urls` in `http_archive` (e.g., via `archive_override` or an untrusted module) and specifies a `jar:file://` URL.
**[Source -> sink]** `http_archive(urls=["jar:file:///etc/passwd"])` -> `GrpcRemoteDownloader.download()` -> Remote server's `FetchBlob` RPC.
**[Exact trust boundary]** Untrusted repository metadata -> Trusted Remote Execution server's downloader logic.
**[Why triage may reject it]** It relies on the Remote Execution server (a separate product, like BuildBarn or EngFlow) actually attempting to fetch `jar:file://` and being vulnerable to it. It is not an exploit in Bazel itself.
**[One best next step]** Check if `HttpUtils.isUrlSupportedByDownloader` prevents `jar:` schemes before it reaches `GrpcRemoteDownloader`.
