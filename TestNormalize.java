import com.google.devtools.build.lib.vfs.PathFragment;

public class TestNormalize {
    public static void main(String[] args) {
        PathFragment pf = PathFragment.create("/tmp/out/../foo");
        System.out.println(pf.getPathString());
    }
}
