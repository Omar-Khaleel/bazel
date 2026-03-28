import com.google.devtools.build.lib.vfs.PathFragment;

public class TestPathFragment {
    public static void main(String[] args) {
        PathFragment p = PathFragment.create("../../../../etc/passwd");
        System.out.println(p.getPathString());
    }
}
