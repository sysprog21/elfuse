# shellcheck shell=sh
# Compile and run a JVM workload under POSIX sh.
set -e

d=/tmp/elfuse-jvm-work
mkdir -p "$d"
cd "$d"
cat > Main.java << 'EOF'
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

public class Main {
    static String sha256(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : d) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Map<Integer, Integer> m = new HashMap<>();
        for (int i = 0; i < 1000; i++) m.put(i, i * i);
        long collSum = 0;
        for (int v : m.values()) collSum += v;

        Path p = Paths.get("data.bin");
        byte[] payload = new byte[65536];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i & 0xff);
        Files.write(p, payload);
        byte[] back = Files.readAllBytes(p);
        if (!Arrays.equals(payload, back)) {
            System.err.println("file io mismatch");
            System.exit(1);
        }
        String digest = sha256(back);

        ExecutorService ex = Executors.newFixedThreadPool(8);
        List<Future<Integer>> fs = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            final int base = t;
            fs.add(ex.submit(() -> {
                int s = 0;
                for (int i = 0; i < 100000; i++) s += (base + i) & 7;
                return s;
            }));
        }
        long threadSum = 0;
        for (Future<Integer> f : fs) threadSum += f.get();
        ex.shutdown();

        Process pr = new ProcessBuilder("/bin/echo", "child-ok")
                .redirectErrorStream(true).start();
        String childOut = new String(pr.getInputStream().readAllBytes()).trim();
        int rc = pr.waitFor();
        if (rc != 0 || !childOut.equals("child-ok")) {
            System.err.println("subprocess failed: " + childOut);
            System.exit(1);
        }

        if (collSum != 332833500L || threadSum != 2800000L
                || !digest.equals("7daca2095d0438260fa849183dfc67faa459fdf4936e1bc91eec6b281b27e4c2")) {
            System.err.println("sanity failed");
            System.exit(1);
        }
        System.out.println("elfuse-oci-jvm-workload-ok");
    }
}
EOF

javac Main.java
java Main
