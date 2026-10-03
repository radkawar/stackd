import com.google.gson.JsonParser;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.Path;
import org.apache.orc.CompressionKind;
import org.apache.orc.OrcFile;
import org.apache.orc.TypeDescription;
import org.apache.orc.Writer;
import org.apache.orc.tools.convert.JsonReader;

// Apache owns type conversion, encoding, compression and indexes. The input
// contract is NDJSON: zero lines are zero records, not a malformed JSON document.
public final class InventoryEncoder {
  public static void main(String[] args) throws Exception {
    Configuration configuration = new Configuration();
    TypeDescription schema = TypeDescription.fromString(args[0]);
    Path inputPath = new Path(args[1]);
    long size = inputPath.getFileSystem(configuration).getFileStatus(inputPath).getLen();
    try (FSDataInputStream input = inputPath.getFileSystem(configuration).open(inputPath);
        Writer writer = OrcFile.createWriter(new Path(args[2]),
            OrcFile.writerOptions(configuration).setSchema(schema).compress(CompressionKind.ZLIB))) {
      BufferedReader lines = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
      JsonReader reader = new JsonReader(lines.lines().map(JsonParser::parseString).iterator(),
          input, size, schema, "yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
      var batch = schema.createRowBatch();
      while (reader.nextBatch(batch)) {
        writer.addRowBatch(batch);
      }
    }
  }
}
