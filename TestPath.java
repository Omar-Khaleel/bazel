package com.google.devtools.build.lib.vfs;

public class TestPath {
    public static void main(String[] args) {
        PathFragment p = PathFragment.create("../../../../etc/passwd");
        System.out.println(p.getPathString());
    }
}
