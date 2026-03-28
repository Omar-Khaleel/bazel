[Label]
strong

[Why]
Bazel's `RemoteExecutionService` downloads all files contained in an `ActionResult` without verifying that the paths in the remote cache response actually correspond to the declared outputs of the cached action. If an attacker shares a remote cache and uploads a poisoned `ActionResult` containing a malicious `OutputFile`, they can write arbitrary files to the local host's `execRoot` when a victim gets a cache hit. This overwrites trusted local artifacts, such as compiler toolchains, leading to Remote Code Execution on the victim's host.

[Attacker model]
The attacker and victim share a Remote Cache (e.g., via `--remote_cache` pointing to Google RBE or an open-source project cache). The attacker uploads a poisoned `ActionResult` for a common compilation action (e.g., compiling `abseil`), containing the legitimate object file plus a malicious `OutputFile` pointing to `bazel-out/host/bin/clang`. The victim builds a target that depends on the cached action. The attacker does NOT need to modify the victim's codebase.

[Source -> sink]
1. `RemoteExecutionService.downloadOutputs()` iterates over `result.getOutputFilesList()`.
2. `parseActionResultMetadata()` converts each `outputFile.getPath()` to a `localPath` via `remotePathResolver.outputPathToLocalPath()` (which resolves against `execRoot`).
3. `shouldDownload()` returns `true` because `--remote_download_outputs=all` is the default.
4. `downloadOutputs` downloads the file to `tmpPath` and calls `moveOutputsToFinalLocation`.
5. `tmpPath.renameTo(realPath)` executes `Files.move(..., REPLACE_EXISTING)`, overwriting the victim's local `clang` binary inside `execRoot`.

[Exact trust boundary]
Untrusted/shared Remote Cache `ActionResult` metadata (which the attacker poisoned) -> Trusted local Bazel host orchestrating action output materialization directly into the execution root.

[Why triage may reject it]
Triage may claim that sharing a remote cache with untrusted users inherently implies full trust in the cache's contents, and caching should only be shared among trusted entities. However, Bazel's action cache is designed to be content-addressable and bounded strictly to the action's *declared* outputs. Blindly materializing undeclared files from an action cache hit violates the hermeticity of the Action Graph and allows a single cache hit to overwrite arbitrary local execution state.

[One best next step]
Modify a Bazel client to upload a poisoned `ActionResult` containing an extra `OutputFile` mapped to a local toolchain binary, then verify that a clean Bazel client querying that action overwrites its local toolchain and executes the payload.

---

[Label]
strong

[Why]
Bazel's `RemoteExecutionService` extracts `TreeArtifacts` (directory outputs) fetched from a Remote Cache using `Path.getRelative()` without validating that the `FileNode` names remain within the TreeArtifact's root directory. Furthermore, files inside a `TreeArtifact` are always downloaded because `shouldDownloadOutput` returns `true` for them, completely bypassing `--remote_download_minimal`. This allows a malicious remote cache hit to break out of the TreeArtifact and overwrite arbitrary files in `execRoot`.

[Attacker model]
Same as above: The attacker and victim share a Remote Cache. The attacker uploads an `ActionResult` where a declared `TreeArtifact` (Directory output) contains a maliciously named `FileNode` with `../` sequences (e.g., `../../../../bazel-out/host/bin/clang`). The victim builds the target with `--remote_download_minimal` and fetches the poisoned output.

[Source -> sink]
1. `RemoteExecutionService.parseDirectory()` loops over `dir.getFilesList()`.
2. It constructs the file path via `parent.getRelative(unicodeToInternal(file.getName()))`, which resolves `../` upwards without bounding it to `parent`.
3. `shouldDownload()` returns `true` because the parent `TreeArtifact` matches the requested download pattern, bypassing `--remote_download_minimal` checks.
4. `downloadOutputs` writes the file, overwriting binaries inside `execRoot`.

[Exact trust boundary]
Untrusted Remote Cache `TreeArtifact` metadata (`FileNode` names) -> Trusted local Bazel host materializing directories into `execRoot`.

[Why triage may reject it]
Same as above (shared cache trust model).

[One best next step]
Audit `RemoteExecutionService.parseDirectory` to confirm that `parent.getRelative(file.getName())` effectively resolves `../` out of the TreeArtifact's bounds and write a test case to execute the overwrite under `--remote_download_minimal`.

---

[Label]
dead

[Why]
If an attacker creates a `java_binary` or `sh_test` with a malicious `runfiles` path containing `../`, they might attempt to trick Bazel into creating symlinks outside the runfiles tree during `RunfilesTreeUpdater.updateRunfilesTree`. However, Bazel uses `PathFragment.segments()` to walk the tree, and `Path.getChild("..")` explicitly calls `FileSystemUtils.checkBaseName`, which throws an `IllegalArgumentException` and crashes the build. It cannot be used to overwrite files or create arbitrary symlinks.

[Attacker model]
Untrusted repository defines a target with maliciously crafted `runfiles` metadata. Victim builds the target.

[Source -> sink]
`DefaultInfo(runfiles=...)` -> `SymlinkTreeHelper.createSymlinks` -> `Directory.walk` -> `Path.getChild("..")` -> `IllegalArgumentException`.

[Exact trust boundary]
Untrusted `BUILD` file runfiles paths -> Trusted host `RunfilesTreeUpdater`.

[Why triage may reject it]
It crashes rather than exploiting.

[One best next step]
None. It's solidly mitigated by `checkBaseName`.

---

[Label]
dead

[Why]
`VendorManager.getVendorPathForUrl` uses `URLDecoder.decode` on the registry URL's path, turning `%2E%2E%2F` into `../../`, and passes it to `Path.getRelative()` without verifying if the result escapes the `vendorDirectory`. While this constitutes a path traversal, Bazel strictly appends fixed filenames (like `source.json` or `bazel_registry.json`) to the URL. The attacker can only create directories and write fixed JSON filenames (e.g., `/etc/passwd/modules/foo/1.0/source.json`), making it unexploitable for overwriting host files.

[Attacker model]
Attacker provides an untrusted `.bazelrc` with a `--registry` flag containing `%2E%2E%2F`. Victim clones repo and runs `bazel vendor`.

[Source -> sink]
`.bazelrc` `--registry` flag -> `VendorManager.getVendorPathForUrl` -> `vendorDirectory.getRelative(path)` -> `FileSystemUtils.writeContent`.

[Exact trust boundary]
Untrusted project config -> Trusted host `bazel vendor` materialization.

[Why triage may reject it]
Writing `source.json` into newly created directories provides no meaningful capability delta.

[One best next step]
None. The strict filename constraints neutralize the traversal.

---

[Label]
dead

[Why]
An attacker can modify the `MODULE.bazel.lock` file in a PR to inject malicious repository configurations (like altering `http_archive` URLs) into `generatedRepoSpecs`. `SingleExtensionEvalFunction` trusts these outputs as long as the inputs (e.g., `.bzl` file hashes) match the lockfile, allowing the attacker to spoof an extension's execution results. However, modifying checked-in repo state to achieve execution is a known local-only self-attack ("user builds untrusted code"), because the attacker could just as easily modify a `BUILD` or `.bzl` file directly to achieve RCE.

[Attacker model]
Attacker submits a PR modifying only the `MODULE.bazel.lock` file to change a repo URL, bypassing reviewer scrutiny of `.bzl` or `BUILD` files. Victim checks out PR and builds.

[Source -> sink]
`MODULE.bazel.lock` `generatedRepoSpecs` -> `SingleExtensionEvalFunction.tryGettingValueFromLockFile` -> `BzlmodRepoRuleFunction`.

[Exact trust boundary]
"Reviewed" `.bzl` files vs. unreviewed `MODULE.bazel.lock` cache -> Trusted Bazel repository fetching orchestration.

[Why triage may reject it]
Lockfile modifications are part of the repository state and are expected to be reviewed. This is a reviewer process issue, not a Bazel security boundary failure.

[One best next step]
None.
