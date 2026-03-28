Wait, `action.getSpawn().getOutputFiles()` gets the DECLARED outputs of the action.
In `RemoteExecutionService.java`, `downloadOutputs` does iterate over `metadata.files()` to fetch files from `ActionResult`.
Does it check if the files in `metadata.files()` are present in `action.getSpawn().getOutputFiles()`?
```java
    for (FileMetadata file : metadata.files()) {
      if (realToTmpPath.containsKey(file.path)) {
        continue;
      }

      var execPath = file.path.relativeTo(execRoot);
      var isInMemoryOutputFile = inMemoryOutput != null && execPath.equals(inMemoryOutputPath);
      if (!isInMemoryOutputFile && shouldDownload(result, execPath, /* treeRootExecPath= */ null)) {
...
```
`shouldDownload` checks `RemoteOutputChecker.shouldDownloadOutput`:
```java
  public boolean shouldDownloadOutput(
      PathFragment execPath, @Nullable PathFragment treeRootExecPath) {
    if (pathsToSkip.contains(execPath)) {
      return false;
    }
    return outputsMode == RemoteOutputsMode.ALL
        || pathsToDownload.contains(execPath)
        || matchesPattern(execPath)
        || (treeRootExecPath != null && matchesPattern(treeRootExecPath));
  }
```
If `outputsMode == RemoteOutputsMode.ALL`, it returns `true`.
Wait, in `RemoteOutputsMode.ALL`, `pathsToDownload` is NOT checked!
Does `downloadOutputs` perform any OTHER check against `action.getSpawn().getOutputFiles()`?
There is ABSOLUTELY NO CHECK that verifies `execPath` is an expected output of the action!
Wait! Is it verified AFTER download?
```java
    if (result.success()) {
      // Check that all mandatory outputs are created.
      var missingMandatoryOutput = result.maybeGetMissingMandatoryOutput(action);
      if (missingMandatoryOutput.isPresent()) {
        throw new IOException(
            "mandatory output %s was not created"
                .formatted(prettyPrint(missingMandatoryOutput.get())));
      }
```
`maybeGetMissingMandatoryOutput` only checks if the EXPECTED outputs are present.
It DOES NOT check if there are UNDECLARED outputs that were downloaded!
So the attacker CAN write an undeclared output to any path inside `execRoot`!
This completely proves Lead 1.

Can they overwrite a meaningful file inside `execRoot`?
Yes. `bazel-out/host/bin/` contains local tools built for the host (e.g. `protoc`, compilers, generators).
If the attacker overwrites `bazel-out/host/bin/protoc`, the next action that uses `protoc` will execute the attacker's binary.
Since it's an action cache hit, the attacker just needs to upload the malicious `ActionResult` to a shared action cache.

Is this a boundary failure?
Yes! The shared remote cache is assumed to be content-addressable and bounded by action outputs.
If an attacker can use a cache hit to write arbitrary undeclared files to the local host, they are escaping the bounds of the Action Graph and the caching mechanism. This is a severe sandbox escape / Confused Deputy.

What about Lead 2: TreeArtifacts?
Can a `FileNode` name in a `Tree` message contain `../`?
Wait, `parseDirectory` loops through `dir.getFilesList()`.
`dir` is a `Directory` Protobuf message from `Tree.parseFrom(...)`.
Does `Directory` Protobuf enforce any validation on `FileNode.name`?
Protobuf parsing is generally just reading the bytes.
In `RemoteExecutionService.parseActionResultMetadata`, it calls `Tree.parseFrom(treeBytes, ExtensionRegistry.getEmptyRegistry())`.
Then it passes `directoryTree.getRoot()` to `parseDirectory`.
There is NO validation of `file.getName()`!
It directly calls `parent.getRelative(unicodeToInternal(file.getName()))`!
`unicodeToInternal` just converts strings to Latin1.
`parent` is the `execRoot.getRelative(outputPath)`.
`parent.getRelative` resolves `../`!
If `file.getName()` is `../../../../bazel-out/host/bin/clang`, `parent.getRelative(".../clang")` resolves it.
And then `downloadOutputs` uses `file.path.relativeTo(execRoot)`.
If the path is outside `execRoot`, it throws. But if it's inside `execRoot`, it proceeds.
And since it's inside a `TreeArtifact` (where `treeRootExecPath` matches the declared output), `shouldDownload` returns TRUE even if `--remote_download_minimal` is set!

Wait! Does `Path.getRelative()` throw an exception if the path string contains `/`?
In `Path.java`:
```java
  public Path getRelative(String other) {
    checkNotNull(other);
    return new Path(pathFragment.getRelative(other), fileSystem);
  }
```
It uses `PathFragment.getRelative(String other)`.
It DOES NOT throw an exception for `/`!
Only `Path.getChild()` throws an exception for `/` (via `checkBaseName`).
`getRelative` allows any relative path, including those with `../` and `/`!

So Lead 2 is COMPLETELY PROVEN!
A `TreeArtifact` `FileNode` can contain `../` and `/`, and it will escape the `TreeArtifact` and overwrite arbitrary files inside `execRoot`!
This bypasses ALL `--remote_download_minimal` restrictions, making the exploit work regardless of the user's remote caching configuration!

Is there any protobuf-level validation in Bazel for `Tree` messages?
Let's check if Bazel validates `Tree` anywhere.
Wait, let's look at `RemoteExecutionService.parseDirectory`.
It literally just does `parent.getRelative(unicodeToInternal(file.getName()))`.
There is no `PathFragment.isNormalizedRelativePath` or `FileSystemUtils.checkBaseName`.
It is completely unsanitized!

So both Lead 1 and Lead 2 are perfectly valid and form a coherent attack vector on Bazel's Remote Cache integration.
Lead 1 shows that undeclared outputs in an `ActionResult` overwrite arbitrary `execRoot` files if `--remote_download_outputs=all` (the default).
Lead 2 takes this further: it proves that by embedding the malicious files inside a `TreeArtifact` (Directory) message, the path traversal (`../`) works against `parent.getRelative()`, and the file is *always downloaded* regardless of `--remote_download_outputs` because the TreeArtifact itself is requested.

This is a phenomenal capability delta!
