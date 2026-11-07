// JVM real-workload benchmark: the jvm row of the syscall-frequency ranking
// of elfuse (collections, file I/O, SHA-256, 8 threads, a subprocess).
// Compiled and run by tests/bench-oci/jvm.sh inside eclipse-temurin:21.
//
// SPDX-License-Identifier: Apache-2.0

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class Bench {
    public static void main(String[] args) throws Exception {
        long total = 0;

        Map<String, Integer> counts = new HashMap<>();
        TreeMap<Integer, String> ordered = new TreeMap<>();
        for (int i = 0; i < 200_000; i++) {
            String key = "k" + (i % 1000);
            counts.merge(key, 1, Integer::sum);
            ordered.put(i % 5000, key);
        }
        total += counts.size() + ordered.size();

        Path dir = Files.createTempDirectory("bench-jvm.");
        for (int i = 0; i < 200; i++) {
            Path file = dir.resolve("f" + i + ".txt");
            Files.writeString(file, ("line " + i + "\n").repeat(32));
            total += Files.readString(file).length();
            Files.delete(file);
        }
        Files.delete(dir);

        List<Worker> workers = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            workers.add(new Worker(i));
        }
        for (Worker w : workers) {
            w.start();
        }
        for (Worker w : workers) {
            w.join();
            total += w.digestByte();
        }

        Process child = new ProcessBuilder("sh", "-c", "echo 42").start();
        total += Integer.parseInt(new String(child.getInputStream().readAllBytes()).trim());
        if (child.waitFor() != 0) {
            throw new IllegalStateException("subprocess failed");
        }

        System.out.println(total);
    }
}
