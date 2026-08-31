package deobf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Self-running JAR stub. Decrypts the wrapped original JAR (DEOBFW01 +
 * XChaCha20-Poly1305) in-process and either invokes the original Main-Class
 * or injects classes into a mod loader classpath.
 */
public final class Loader {
    private static final byte[] MAGIC = new byte[] {'D', 'E', 'O', 'B', 'F', 'W', '0', '1'};
    private static final BigInteger POLY_P = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5));
    private static final BigInteger POLY_MASK =
            new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16);
    private static final BigInteger MASK128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

    private static final Object LOCK = new Object();
    private static boolean installed;
    private static Path decryptedJar;
    private static Path classesOnlyJar;
    private static Properties meta = new Properties();

    public static void main(String[] args) throws Exception {
        install();
        String mainClass = originalMainClass();
        if (mainClass == null || mainClass.length() == 0) {
            return;
        }
        Path full = decryptedJar();
        if (full == null) {
            throw new IllegalStateException("DEOBF payload was not decrypted");
        }
        List urls = new ArrayList();
        urls.add(full.toUri().toURL());
        List nested = extractNestedJars(full);
        for (int i = 0; i < nested.size(); i++) {
            urls.add(((Path) nested.get(i)).toUri().toURL());
        }
        URL[] arr = (URL[]) urls.toArray(new URL[urls.size()]);
        URLClassLoader cl = new URLClassLoader(arr, Loader.class.getClassLoader());
        Thread.currentThread().setContextClassLoader(cl);
        Class cls = Class.forName(mainClass, true, cl);
        Method m = cls.getMethod("main", String[].class);
        String[] a = args == null ? new String[0] : args;
        try {
            m.invoke(null, new Object[] { a });
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable c = e.getCause();
            if (c instanceof Exception) {
                throw (Exception) c;
            }
            if (c instanceof Error) {
                throw (Error) c;
            }
            throw e;
        }
    }

    public static void install() {
        synchronized (LOCK) {
            if (installed) {
                return;
            }
            try {
                doInstall();
                installed = true;
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException("DEOBF install failed", e);
            }
        }
    }

    public static Path decryptedJar() {
        install();
        return decryptedJar;
    }

    public static Path classesOnlyJar() {
        install();
        return classesOnlyJar;
    }

    public static String originalMainClass() {
        install();
        String v = meta.getProperty("original-main-class", "");
        return v.trim();
    }

    public static String originalPluginMain() {
        install();
        String v = meta.getProperty("original-plugin-main", "");
        return v.trim();
    }

    static void addToLoader(ClassLoader cl, Path path) {
        if (cl == null || path == null) {
            return;
        }
        tryAddUrl(cl, path);
    }

    private static void doInstall() throws Exception {
        Located loc = locatePayload();
        byte[] jar = decryptWrapper(loc.key, loc.wrapped);
        if (loc.meta != null) {
            meta = loc.meta;
        }
        Path full = Files.createTempFile("deobf-full-", ".jar");
        full.toFile().deleteOnExit();
        Files.write(full, jar);
        decryptedJar = full;

        byte[] classesOnly = buildClassesOnly(jar);
        Path cls = Files.createTempFile("deobf-cls-", ".jar");
        cls.toFile().deleteOnExit();
        Files.write(cls, classesOnly);
        classesOnlyJar = cls;

        injectPath(cls);
        List nested = extractNestedJarsFromBytes(jar, true);
        for (int i = 0; i < nested.size(); i++) {
            injectPath((Path) nested.get(i));
        }
    }

    private static final class Located {
        byte[] key;
        byte[] wrapped;
        Properties meta;
    }

    private static Located locatePayload() throws IOException {
        Located fromSelf = readFromClass(Loader.class);
        Located preferred = null;
        ClassLoader[] loaders = new ClassLoader[] {
            Thread.currentThread().getContextClassLoader(),
            Loader.class.getClassLoader(),
            ClassLoader.getSystemClassLoader()
        };
        for (int i = 0; i < loaders.length; i++) {
            ClassLoader cl = loaders[i];
            if (cl == null) {
                continue;
            }
            Enumeration urls;
            try {
                urls = cl.getResources("deobf/meta.properties");
            } catch (IOException e) {
                continue;
            }
            while (urls.hasMoreElements()) {
                URL url = (URL) urls.nextElement();
                Located loc = readFromMetaUrl(url);
                if (loc == null) {
                    continue;
                }
                if (loc.meta != null && "true".equalsIgnoreCase(loc.meta.getProperty("full-original", ""))) {
                    return loc;
                }
                if (preferred == null) {
                    preferred = loc;
                }
            }
        }
        if (preferred != null) {
            return preferred;
        }
        if (fromSelf != null) {
            return fromSelf;
        }
        throw new FileNotFoundException("deobf/payload.bin");
    }

    private static Located readFromClass(Class anchor) throws IOException {
        InputStream metaIn = anchor.getResourceAsStream("meta.properties");
        InputStream keyIn = anchor.getResourceAsStream("key.bin");
        InputStream payIn = anchor.getResourceAsStream("payload.bin");
        if (keyIn == null || payIn == null) {
            return null;
        }
        Located loc = new Located();
        loc.key = readAll(keyIn);
        loc.wrapped = readAll(payIn);
        loc.meta = new Properties();
        if (metaIn != null) {
            loc.meta.load(metaIn);
            metaIn.close();
        }
        keyIn.close();
        payIn.close();
        return loc;
    }

    private static Located readFromMetaUrl(URL metaUrl) {
        try {
            String s = metaUrl.toExternalForm();
            if (!s.endsWith("meta.properties")) {
                return null;
            }
            String base = s.substring(0, s.length() - "meta.properties".length());
            Located loc = new Located();
            loc.meta = new Properties();
            InputStream in = metaUrl.openStream();
            try {
                loc.meta.load(in);
            } finally {
                in.close();
            }
            loc.key = readAll(new URL(base + "key.bin").openStream());
            loc.wrapped = readAll(new URL(base + "payload.bin").openStream());
            if (loc.key.length != 32) {
                return null;
            }
            return loc;
        } catch (Exception e) {
            return null;
        }
    }

    private static void injectPath(Path path) {
        if (path == null) {
            return;
        }
        if (invokeAddToClassPath("net.fabricmc.loader.impl.launch.FabricLauncherBase", path)) {
            return;
        }
        if (invokeAddToClassPath("org.quiltmc.loader.impl.launch.QuiltLauncherBase", path)) {
            return;
        }
        ClassLoader ctx = Thread.currentThread().getContextClassLoader();
        if (tryAddUrl(ctx, path)) {
            return;
        }
        tryAddUrl(Loader.class.getClassLoader(), path);
        tryAddUrl(ClassLoader.getSystemClassLoader(), path);
    }

    private static boolean invokeAddToClassPath(String launcherBase, Path path) {
        try {
            Class c = Class.forName(launcherBase);
            Object launcher = c.getMethod("getLauncher").invoke(null);
            Method m;
            try {
                m = launcher.getClass().getMethod("addToClassPath", Path.class);
                m.invoke(launcher, path);
                return true;
            } catch (NoSuchMethodException e) {
                m = launcher.getClass().getMethod("addToClassPath", Path.class, String[].class);
                m.invoke(launcher, path, new String[0]);
                return true;
            }
        } catch (Throwable ignored) {
            return false;
        }
    }

    static boolean tryAddUrl(ClassLoader cl, Path path) {
        if (cl == null || path == null) {
            return false;
        }
        URL url;
        try {
            url = path.toUri().toURL();
        } catch (Exception e) {
            return false;
        }
        Class c = cl.getClass();
        while (c != null) {
            try {
                Method m = c.getDeclaredMethod("addURL", URL.class);
                m.setAccessible(true);
                m.invoke(cl, url);
                return true;
            } catch (Throwable ignored) {
            }
            try {
                Method m = c.getDeclaredMethod("appendToClassPathForInstrumentation", String.class);
                m.setAccessible(true);
                m.invoke(cl, path.toAbsolutePath().toString());
                return true;
            } catch (Throwable ignored) {
            }
            c = c.getSuperclass();
        }
        return false;
    }

    private static List extractNestedJars(Path fullJar) throws IOException {
        byte[] data = Files.readAllBytes(fullJar);
        return extractNestedJarsFromBytes(data, false);
    }

    private static List extractNestedJarsFromBytes(byte[] jar, boolean classesOnlyNested) throws IOException {
        List out = new ArrayList();
        ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(jar));
        try {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.isDirectory()) {
                    continue;
                }
                String name = e.getName().replace('\\', '/');
                if (!name.toLowerCase(Locale.ROOT).endsWith(".jar")) {
                    continue;
                }
                byte[] nested = readRemaining(zis);
                if (classesOnlyNested) {
                    nested = buildClassesOnly(nested);
                }
                String safe = name.replace('/', '_').replace('\\', '_');
                Path tmp = Files.createTempFile("deobf-n-" + safe + "-", ".jar");
                tmp.toFile().deleteOnExit();
                Files.write(tmp, nested);
                out.add(tmp);
            }
        } finally {
            zis.close();
        }
        return out;
    }

    private static byte[] buildClassesOnly(byte[] jar) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(bos);
        ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(jar));
        try {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.isDirectory()) {
                    continue;
                }
                String name = e.getName().replace('\\', '/');
                if (isDroppedFromClassesOnly(name)) {
                    continue;
                }
                byte[] data = readRemaining(zis);
                String lower = name.toLowerCase(Locale.ROOT);
                if (lower.endsWith(".jar")) {
                    try {
                        data = buildClassesOnly(data);
                    } catch (Exception ignored) {
                    }
                } else if (!lower.endsWith(".class")) {
                    continue;
                }
                ZipEntry out = new ZipEntry(name);
                zos.putNextEntry(out);
                zos.write(data);
                zos.closeEntry();
            }
        } finally {
            zis.close();
            zos.close();
        }
        return bos.toByteArray();
    }

    private static boolean isDroppedFromClassesOnly(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        String base = name;
        int slash = name.lastIndexOf('/');
        if (slash >= 0) {
            base = name.substring(slash + 1);
        }
        String baseLower = base.toLowerCase(Locale.ROOT);
        if (baseLower.equals("fabric.mod.json")
                || baseLower.equals("quilt.mod.json")
                || baseLower.equals("plugin.yml")
                || baseLower.equals("paper-plugin.yml")
                || baseLower.equals("bungee.yml")
                || baseLower.equals("velocity-plugin.json")
                || baseLower.equals("mods.toml")
                || baseLower.equals("neoforge.mods.toml")
                || baseLower.equals("mcmod.info")
                || baseLower.equals("pack.mcmeta")) {
            return true;
        }
        if (lower.endsWith(".java") || lower.endsWith(".kt") || lower.endsWith(".kts")
                || lower.endsWith(".scala") || lower.endsWith(".mjs") || lower.endsWith(".map")) {
            return true;
        }
        return false;
    }

    private static byte[] readResource(String name) throws IOException {
        InputStream in = Loader.class.getResourceAsStream(name);
        if (in == null) {
            throw new FileNotFoundException("deobf/" + name);
        }
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try {
            return readRemaining(in);
        } finally {
            in.close();
        }
    }

    private static byte[] readRemaining(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) >= 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    static byte[] decryptWrapper(byte[] key, byte[] wrapped) {
        if (wrapped.length < 34 + 16) {
            throw new SecurityException("truncated DEOBF wrapper");
        }
        for (int i = 0; i < 8; i++) {
            if (wrapped[i] != MAGIC[i]) {
                throw new SecurityException("not a DEOBF wrapper");
            }
        }
        if (wrapped[8] != 1) {
            throw new SecurityException("unsupported wrapper version");
        }
        byte[] nonce = Arrays.copyOfRange(wrapped, 10, 34);
        byte[] ctAndTag = Arrays.copyOfRange(wrapped, 34, wrapped.length);
        return open(key, nonce, ctAndTag);
    }

    static byte[] open(byte[] key, byte[] nonce24, byte[] ctAndTag) {
        if (key.length != 32 || nonce24.length != 24 || ctAndTag.length < 16) {
            throw new SecurityException("invalid AEAD parameters");
        }
        byte[] nonce16 = Arrays.copyOfRange(nonce24, 0, 16);
        byte[] subkey = hchacha20(key, nonce16);
        byte[] nonce12 = new byte[12];
        System.arraycopy(nonce24, 16, nonce12, 4, 8);
        int ctLen = ctAndTag.length - 16;
        byte[] ct = Arrays.copyOfRange(ctAndTag, 0, ctLen);
        byte[] tag = Arrays.copyOfRange(ctAndTag, ctLen, ctAndTag.length);
        byte[] block0 = chachaBlock(subkey, nonce12, 0);
        byte[] polyKey = Arrays.copyOf(block0, 32);
        byte[] macData = polyData(ct);
        byte[] expected = poly1305(polyKey, macData);
        if (!constEq(expected, tag)) {
            throw new SecurityException("wrapper authentication failed");
        }
        return chachaXor(subkey, nonce12, 1, ct);
    }

    static byte[] seal(byte[] key, byte[] nonce24, byte[] plaintext) {
        byte[] nonce16 = Arrays.copyOfRange(nonce24, 0, 16);
        byte[] subkey = hchacha20(key, nonce16);
        byte[] nonce12 = new byte[12];
        System.arraycopy(nonce24, 16, nonce12, 4, 8);
        byte[] ct = chachaXor(subkey, nonce12, 1, plaintext);
        byte[] block0 = chachaBlock(subkey, nonce12, 0);
        byte[] polyKey = Arrays.copyOf(block0, 32);
        byte[] tag = poly1305(polyKey, polyData(ct));
        byte[] out = new byte[ct.length + 16];
        System.arraycopy(ct, 0, out, 0, ct.length);
        System.arraycopy(tag, 0, out, ct.length, 16);
        return out;
    }

    private static byte[] polyData(byte[] ct) {
        int pad = (16 - (ct.length % 16)) % 16;
        byte[] data = new byte[ct.length + pad + 16];
        System.arraycopy(ct, 0, data, 0, ct.length);
        storeU64(data, ct.length + pad, 0);
        storeU64(data, ct.length + pad + 8, ct.length);
        return data;
    }

    static byte[] hchacha20(byte[] key, byte[] nonce16) {
        int[] s = new int[16];
        s[0] = 0x61707865;
        s[1] = 0x3320646e;
        s[2] = 0x79622d32;
        s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) {
            s[4 + i] = le32(key, i * 4);
        }
        for (int i = 0; i < 4; i++) {
            s[12 + i] = le32(nonce16, i * 4);
        }
        chachaRounds(s);
        byte[] out = new byte[32];
        storeLe32(out, 0, s[0]);
        storeLe32(out, 4, s[1]);
        storeLe32(out, 8, s[2]);
        storeLe32(out, 12, s[3]);
        storeLe32(out, 16, s[12]);
        storeLe32(out, 20, s[13]);
        storeLe32(out, 24, s[14]);
        storeLe32(out, 28, s[15]);
        return out;
    }

    static byte[] chachaBlock(byte[] key, byte[] nonce12, int counter) {
        int[] init = new int[16];
        init[0] = 0x61707865;
        init[1] = 0x3320646e;
        init[2] = 0x79622d32;
        init[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) {
            init[4 + i] = le32(key, i * 4);
        }
        init[12] = counter;
        init[13] = le32(nonce12, 0);
        init[14] = le32(nonce12, 4);
        init[15] = le32(nonce12, 8);
        int[] s = init.clone();
        chachaRounds(s);
        byte[] out = new byte[64];
        for (int i = 0; i < 16; i++) {
            storeLe32(out, i * 4, s[i] + init[i]);
        }
        return out;
    }

    private static byte[] chachaXor(byte[] key, byte[] nonce12, int counter, byte[] input) {
        byte[] out = new byte[input.length];
        int off = 0;
        int n = counter;
        while (off < input.length) {
            byte[] block = chachaBlock(key, nonce12, n);
            int take = Math.min(64, input.length - off);
            for (int i = 0; i < take; i++) {
                out[off + i] = (byte) (input[off + i] ^ block[i]);
            }
            off += take;
            n++;
        }
        return out;
    }

    private static void chachaRounds(int[] s) {
        for (int r = 0; r < 10; r++) {
            qr(s, 0, 4, 8, 12);
            qr(s, 1, 5, 9, 13);
            qr(s, 2, 6, 10, 14);
            qr(s, 3, 7, 11, 15);
            qr(s, 0, 5, 10, 15);
            qr(s, 1, 6, 11, 12);
            qr(s, 2, 7, 8, 13);
            qr(s, 3, 4, 9, 14);
        }
    }

    private static void qr(int[] s, int a, int b, int c, int d) {
        s[a] += s[b];
        s[d] = Integer.rotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d];
        s[b] = Integer.rotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b];
        s[d] = Integer.rotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d];
        s[b] = Integer.rotateLeft(s[b] ^ s[c], 7);
    }

    static byte[] poly1305(byte[] key, byte[] msg) {
        BigInteger r = fromLe(key, 0, 16).and(POLY_MASK);
        BigInteger s = fromLe(key, 16, 16);
        BigInteger h = BigInteger.ZERO;
        for (int i = 0; i < msg.length; i += 16) {
            int n = Math.min(16, msg.length - i);
            byte[] block = new byte[n + 1];
            System.arraycopy(msg, i, block, 0, n);
            block[n] = 1;
            h = h.add(fromLe(block, 0, n + 1)).multiply(r).mod(POLY_P);
        }
        h = h.add(s).and(MASK128);
        return toLe(h, 16);
    }

    private static BigInteger fromLe(byte[] b, int off, int len) {
        byte[] be = new byte[len];
        for (int i = 0; i < len; i++) {
            be[len - 1 - i] = b[off + i];
        }
        return new BigInteger(1, be);
    }

    private static byte[] toLe(BigInteger x, int len) {
        byte[] out = new byte[len];
        byte[] be = x.toByteArray();
        int n = Math.min(be.length, len);
        for (int i = 0; i < n; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static int le32(byte[] b, int i) {
        return (b[i] & 0xff)
                | ((b[i + 1] & 0xff) << 8)
                | ((b[i + 2] & 0xff) << 16)
                | ((b[i + 3] & 0xff) << 24);
    }

    private static void storeLe32(byte[] b, int i, int v) {
        b[i] = (byte) v;
        b[i + 1] = (byte) (v >>> 8);
        b[i + 2] = (byte) (v >>> 16);
        b[i + 3] = (byte) (v >>> 24);
    }

    private static void storeU64(byte[] b, int i, long v) {
        for (int n = 0; n < 8; n++) {
            b[i + n] = (byte) (v >>> (8 * n));
        }
    }

    private static boolean constEq(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < a.length; i++) {
            r |= a[i] ^ b[i];
        }
        return r == 0;
    }
}
