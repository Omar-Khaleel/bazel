import com.google.devtools.build.lib.vfs.PathFragment;

public class TestTarSymlink {
    public static void main(String[] args) {
        PathFragment targetName = PathFragment.create("/../../etc/passwd");
        System.out.println("targetName.isAbsolute(): " + targetName.isAbsolute());

        targetName = PathFragment.create("../../../etc/passwd");
        System.out.println("targetName.isAbsolute(): " + targetName.isAbsolute());
    }
}
