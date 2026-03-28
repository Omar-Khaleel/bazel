import java.net.URI;
import java.net.URL;

public class TestURL {
    public static void main(String[] args) throws Exception {
        URI uri = new URI("https://bcr.bazel.build/%2E%2E/%2E%2E/tmp/pwned");
        URL url = uri.toURL();
        System.out.println("url: " + url.toString());

        uri = new URI("https://bcr.bazel.build/..%2F..%2Ftmp%2Fpwned");
        url = uri.toURL();
        System.out.println("url: " + url.toString());
    }
}
