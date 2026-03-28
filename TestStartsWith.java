import com.google.devtools.build.lib.vfs.PathFragment;

public class TestStartsWith {
    public static void main(String[] args) {
        PathFragment dest = PathFragment.create("/tmp/out");
        PathFragment filePath = PathFragment.create("/tmp/out/../foo");

        System.out.println(dest.getPathString());
        System.out.println(filePath.getPathString());
        System.out.println("dest.startsWith(filePath)? " + dest.startsWith(filePath));
        System.out.println("filePath.startsWith(dest)? " + filePath.startsWith(dest));

        PathFragment filePath2 = PathFragment.create("/tmp/out/link");
        PathFragment targetPath = PathFragment.create("/etc/passwd");
        PathFragment resolved = filePath2.getParentDirectory().getRelative(targetPath);

        System.out.println("resolved: " + resolved.getPathString());
        System.out.println("resolved.startsWith(dest)? " + resolved.startsWith(dest));
    }
}
