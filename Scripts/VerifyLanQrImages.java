import java.nio.file.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.multi.qrcode.QRCodeMultiReader;
import java.util.Map;
import java.util.Arrays;

/** Independent PNG and payload verification using Android's bundled ZXing decoder. */
class VerifyLanQrImages {
    private static final class LocatorBudgetExceeded extends RuntimeException {
        private static final long serialVersionUID = 1L;
        LocatorBudgetExceeded() { super(null, null, false, false); }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected the image evidence directory.");
        Path directory = Path.of(args[0]);
        int images = 0;
        try (var paths = Files.list(directory)) {
            for (Path path : paths.filter(p -> p.toString().endsWith(".png")).sorted().toList()) {
                BufferedImage image = ImageIO.read(path.toFile());
                if (image == null || image.getWidth() != image.getHeight()) throw new Exception("Invalid QR image.");
                int side = image.getWidth();
                if (side < 174 || side > 1110 || side % 6 != 0) throw new Exception("Invalid module grid.");
                int[] rgb = image.getRGB(0, 0, side, side, null, 0, side);
                for (int y = 0; y < side; y++) for (int x = 0; x < side; x++) {
                    int color = rgb[y * side + x] & 0xffffff;
                    if (color != 0 && color != 0xffffff) throw new Exception("Nonbinary module pixel.");
                    if ((x < 24 || y < 24 || x >= side - 24 || y >= side - 24) && color != 0xffffff)
                        throw new Exception("The four-module quiet zone was lost.");
                }
                // Match Android's bounded multi-candidate detector. No pure-barcode shortcut.
                int[] locatorPoints = { 0 };
                Map<DecodeHintType, Object> hints = Map.of(DecodeHintType.NEED_RESULT_POINT_CALLBACK,
                    (ResultPointCallback)(point -> { if (++locatorPoints[0] > 12) throw new LocatorBudgetExceeded(); }));
                Result[] results = new QRCodeMultiReader().decodeMultiple(new BinaryBitmap(new HybridBinarizer(
                    new RGBLuminanceSource(side, side, rgb))), hints);
                var payloads = Arrays.stream(results).map(Result::getText).distinct().toList();
                if (payloads.size() != 1) throw new Exception("Missing or ambiguous generated QR image.");
                String actual = payloads.get(0);
                String name = path.getFileName().toString();
                String expected = Files.readString(directory.resolve(name.replace(".png", ".txt")));
                if (!actual.equals(expected)) throw new Exception("Decoded payload changed: " + name);
                images++;
                System.out.println("PASS LAN QR " + name + " pixels=" + side + " characters=" + actual.length());
            }
        }
        if (images != 21) throw new Exception("Expected all 21 published QR vectors, got " + images);
    }
}
