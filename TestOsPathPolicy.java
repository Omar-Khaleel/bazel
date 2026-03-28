import com.google.devtools.build.lib.vfs.UnixOsPathPolicy;
import com.google.devtools.build.lib.vfs.OsPathPolicy;

public class TestOsPathPolicy {
    public static void main(String[] args) {
        UnixOsPathPolicy policy = new UnixOsPathPolicy();
        System.out.println(policy.normalize("/tmp/out/../foo", OsPathPolicy.NEEDS_NORMALIZE));
        System.out.println(policy.normalize("foo/../bar", OsPathPolicy.NEEDS_NORMALIZE));
        System.out.println(policy.normalize("../foo/../bar", OsPathPolicy.NEEDS_NORMALIZE));
    }
}
