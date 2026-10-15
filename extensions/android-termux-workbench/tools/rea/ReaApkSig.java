// Static package-signature verification only. Does not install or execute the APK.
import com.android.apksig.ApkVerifier;
import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public final class ReaApkSig {
    private static String hex(byte[] value) {
        StringBuilder out = new StringBuilder();
        for (byte b : value) out.append(String.format("%02x", b));
        return out.toString();
    }

    private static String quote(String value) {
        String q = String.valueOf((char) 34);
        return q + value + q;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2) throw new IllegalArgumentException("apk [idsig]");
        ApkVerifier.Builder builder = new ApkVerifier.Builder(new File(args[0]));
        boolean idsigPresent = args.length == 2 && new File(args[1]).isFile();
        if (idsigPresent) builder.setV4SignatureFile(new File(args[1]));
        ApkVerifier.Result result = builder.build().verify();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        List<String> certs = new ArrayList<>();
        for (X509Certificate cert : result.getSignerCertificates()) {
            certs.add(hex(sha256.digest(cert.getEncoded())));
        }
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"verified\":").append(result.isVerified()).append(",");
        json.append("\"v1\":").append(result.isVerifiedUsingV1Scheme()).append(",");
        json.append("\"v2\":").append(result.isVerifiedUsingV2Scheme()).append(",");
        json.append("\"v3\":").append(result.isVerifiedUsingV3Scheme()).append(",");
        json.append("\"v31\":").append(result.isVerifiedUsingV31Scheme()).append(",");
        json.append("\"v32\":").append(result.isVerifiedUsingV32Scheme()).append(",");
        json.append("\"v4\":").append(result.isVerifiedUsingV4Scheme()).append(",");
        json.append("\"idsig_present\":").append(idsigPresent).append(",");
        json.append("\"certificate_sha256\":[");
        for (int i = 0; i < certs.size(); i++) {
            if (i > 0) json.append(",");
            json.append(quote(certs.get(i)));
        }
        json.append("],");
        json.append("\"error_count\":").append(result.getAllErrors().size()).append(",");
        json.append("\"warning_count\":").append(result.getWarnings().size());
        json.append("}");
        System.out.println(json);
    }
}
