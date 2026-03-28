[Label]
strong

[Why]
Bazel's `RemoteExecutionService.downloadOutputs()` blindly iterates over the `OutputFile` list from an `ActionResult` without verifying that the paths correspond to the action's declared outputs. When using the default `--remote_download_outputs=all`, Bazel downloads all files provided by a remote cache hit. An attacker sharing a Remote Cache can upload a poisoned `ActionResult` for a common compilation action that includes an extra `OutputFile` pointing to a trusted local binary (e.g., `bazel-out/host/bin/clang`). Bazel overwrites the victim's local toolchain inside `execRoot` during cache materialization, allowing the attacker to execute arbitrary code during the victim's build.

[Attacker model]
The attacker and victim share a Remote Cache (e.g., via `--remote_cache` on Google RBE or a public open-source project cache). The attacker uploads a malicious `ActionResult` containing a legitimate output and an extra, undeclared `OutputFile` pointing to a local toolchain path. The victim builds a target that triggers a cache hit. The attacker does not need to modify the victim's codebase.

[Source -> sink]
1. `ActionResult`'s `OutputFilesList` is iterated in `RemoteExecutionService.parseActionResultMetadata`.
2. `outputFile.getPath()` is resolved via `remotePathResolver.outputPathToLocalPath()` (using `execRoot.getRelative(outputPath)`).
3. `shouldDownloadOutput()` returns `true` for all files under `--remote_download_outputs=all`.
4. `downloadOutputs` downloads the file and calls `tmpPath.renameTo(realPath)`, replacing the existing file on the victim's host.

[Exact trust boundary]
Untrusted/Shared Remote Cache `ActionResult` metadata (which the attacker poisoned) -> Trusted local Bazel host orchestrating action output materialization into `execRoot`.

[Why triage may reject it]
Triage may claim that sharing a remote cache inherently implies full trust in its contents. However, Bazel's action cache relies on content-addressability and is strictly bounded to the action's *declared* outputs. Blindly materializing undeclared extra files from an action cache hit to overwrite arbitrary local execution state violates the hermeticity of the Action Graph and allows a single cache hit to subvert the entire host machine.

[One best next step]
Modify a Bazel client to upload a poisoned `ActionResult` containing an extra `OutputFile` mapped to `bazel-out/host/bin/clang`, then verify that a victim querying that action overwrites its local toolchain and executes the payload.

---

[Label]
strong

[Why]
Bazel's `RemoteExecutionService.parseDirectory()` extracts `TreeArtifacts` (directory outputs) fetched from a Remote Cache by calling `parent.getRelative(unicodeToInternal(file.getName()))` on each `FileNode`. `Path.getRelative()` inherently resolves `../` sequences without bounding them to the parent directory. An attacker can craft a `TreeArtifact` containing a `FileNode` named `../../../../bazel-out/host/bin/clang`, which escapes the TreeArtifact's root and overwrites arbitrary files inside `execRoot`. Furthermore, because the TreeArtifact itself is a declared output, `shouldDownloadOutput()` returns `true` for all its files, *completely bypassing* `--remote_download_minimal` restrictions.

[Attacker model]
The attacker and victim share a Remote Cache. The attacker uploads an `ActionResult` where a declared `TreeArtifact` (Directory output) contains a maliciously named `FileNode` with `../` sequences (e.g., `../../../../bazel-out/host/bin/clang`). The victim builds the target with `--remote_download_minimal` (or `all`) and fetches the poisoned output.

[Source -> sink]
1. `Directory` message `FileNode` is parsed in `RemoteExecutionService.parseDirectory()`.
2. `file.getName()` is passed directly to `parent.getRelative()`, resolving `../` and escaping the TreeArtifact output directory.
3. `shouldDownloadOutput()` evaluates to `true` because the parent `TreeArtifact` matches the requested download pattern.
4. `downloadOutputs` downloads the file to the resolved `execRoot` path, overwriting local binaries via `tmpPath.renameTo(realPath)`.

[Exact trust boundary]
Untrusted Remote Cache `TreeArtifact` metadata (`FileNode` names) -> Trusted local Bazel host materializing directories into `execRoot`.

[Why triage may reject it]
Same as Lead 1 (reliance on shared cache trust).

[One best next step]
Audit `RemoteExecutionService.parseDirectory` to confirm that `parent.getRelative(file.getName())` is completely unsanitized, and write a test case to execute the overwrite against a local compiler under `--remote_download_minimal`.
