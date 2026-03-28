import java.net.URI;

public class TestRelativeURI {
    public static void main(String[] args) throws Exception {
        URI uri = new URI("/foo/bar");
        try {
            System.out.println(uri.toURL());
        } catch (IllegalArgumentException e) {
            System.out.println("Caught: " + e);
        }
    }
}
