package deobf;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Self-running JAR stub. Decrypts the wrapped original JAR (DEOBFW01 +
 * XChaCha20-Poly1305) and launches it with the same JVM via {@code java -jar}.
 */
public final class Loader {
    private static final byte[] MAGIC = new byte[] {'D', 'E', 'O', 'B', 'F', 'W', '0', '1'};
    private static final BigInteger POLY_P = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5));
    private static final BigInteger POLY_MASK =
            new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16);
    private static final BigInteger MASK128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

    public static void main(String[] args) throws Exception {
        byte[] key = readResource("key.bin");
        byte[] wrapped = readResource("payload.bin");
        if (key.length != 32) {
            throw new IllegalStateException("invalid DEOBF key");
        }
        byte[] jar = decryptWrapper(key, wrapped);
        Path tmp = Files.createTempFile("deobf-", ".jar");
        tmp.toFile().deleteOnExit();
        int code = 1;
        try {
            Files.write(tmp, jar);
            File javaBin = new File(new File(System.getProperty("java.home"), "bin"),
                    File.separatorChar == '\\' ? "java.exe" : "java");
            List<String> cmd = new ArrayList<String>();
            cmd.add(javaBin.getPath());
            cmd.add("-jar");
            cmd.add(tmp.toString());
            if (args != null) {
                for (int i = 0; i < args.length; i++) {
                    cmd.add(args[i]);
                }
            }
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.inheritIO();
            code = pb.start().waitFor();
        } finally {
            try {
                Files.deleteIfExists(tmp);
            } catch (Exception ignored) {
            }
        }
        System.exit(code);
    }

    private static byte[] readResource(String name) throws IOException {
        InputStream in = Loader.class.getResourceAsStream(name);
        if (in == null) {
            throw new FileNotFoundException("deobf/" + name);
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) >= 0) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
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
