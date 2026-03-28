import java.net.URI;

public class TestURI {
    public static void main(String[] args) throws Exception {
        URI uri = new URI("https://attacker.com/%2E%2E/%2E%2E/etc/passwd");
        System.out.println("rawPath: " + uri.getRawPath());
        System.out.println("getPath: " + uri.getPath());
        uri = new URI("https://attacker.com/..%2F..%2Fetc%2Fpasswd");
        System.out.println("rawPath: " + uri.getRawPath());
        System.out.println("getPath: " + uri.getPath());
    }
}
