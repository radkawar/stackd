// Native parser projection for the pinned Trino 476 image; never executes SQL.
// API sources: trinodb/trino tag 476, core/trino-parser (SqlParser,
// CreateTableAsSelect, Property, SqlFormatter and ExpressionFormatter).
import com.fasterxml.jackson.databind.ObjectMapper;
import io.trino.sql.ExpressionFormatter;
import io.trino.sql.SqlFormatter;
import io.trino.sql.parser.ParsingException;
import io.trino.sql.parser.SqlParser;
import io.trino.sql.tree.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

class StackdCTAS {
    static Map<String, Object> value(Expression expression) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sql", ExpressionFormatter.formatExpression(expression));
        if (expression instanceof StringLiteral literal) {
            out.put("kind", "string");
            out.put("text", literal.getValue());
        }
        else if (expression instanceof BooleanLiteral literal) {
            out.put("kind", "boolean");
            out.put("boolean", literal.getValue());
        }
        else if (expression instanceof LongLiteral literal) {
            out.put("kind", "integer");
            out.put("text", Long.toString(literal.getParsedValue()));
        }
        else if (expression instanceof io.trino.sql.tree.Array array) {
            out.put("kind", "array");
            out.put("elements", array.getValues().stream().map(StackdCTAS::value).toList());
        }
        else {
            // Expressions passed through to native connector properties are
            // analyzed by Trino itself before its write transaction begins.
            out.put("kind", "expression");
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        Map<String, Object> envelope = new LinkedHashMap<>();
        try {
            Statement statement = new SqlParser().createStatement(Files.readString(Path.of(args[0])));
            if (statement instanceof CreateTableAsSelect ctas) {
                Map<String, Object> plan = new LinkedHashMap<>();
                plan.put("identifier", ctas.getName().getOriginalParts().stream()
                        .map(id -> id.isDelimited() ? id.getValue() : id.getValue().toLowerCase(Locale.ENGLISH)).toList());
                plan.put("query", SqlFormatter.formatSql(ctas.getQuery()));
                plan.put("saveMode", ctas.getSaveMode().name());
                plan.put("withData", ctas.isWithData());
                plan.put("aliases", ctas.getColumnAliases().orElse(List.of()).stream()
                        .map(ExpressionFormatter::formatExpression).toList());
                plan.put("comment", ctas.getComment().orElse(null));
                List<Map<String, Object>> properties = new ArrayList<>();
                for (Property property : ctas.getProperties()) {
                    Map<String, Object> projected = new LinkedHashMap<>();
                    projected.put("name", property.getName().getValue());
                    projected.put("value", property.isSetToDefault()
                            ? Map.of("kind", "default", "sql", "DEFAULT")
                            : value(property.getNonDefaultValue()));
                    properties.add(projected);
                }
                plan.put("properties", properties);
                envelope.put("plan", plan);
            }
        }
        catch (ParsingException error) {
            // Hive syntax is intentionally left to the existing native Spark
            // fallback after Trino reports its ordinary SYNTAX_ERROR.
            envelope.put("syntaxError", error.getMessage());
        }
        System.out.println(new ObjectMapper().writeValueAsString(envelope));
    }
}
