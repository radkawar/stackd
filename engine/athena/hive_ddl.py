"""Project Apache Spark 4.1.3's Hive DDL AST; never execute SQL or access a catalog."""
import base64
import json
import os

from py4j.java_gateway import get_field
from pyspark.errors import ParseException
from pyspark.sql import SparkSession


class UnsupportedDDL(ValueError):
    """A valid native plan whose Athena metadata projection is unavailable."""


def sequence(value):
    return [value.apply(index) for index in range(value.size())]


def mapping(value):
    return {str(pair._1()): str(pair._2()) for pair in sequence(value.toSeq())}


def optional(value):
    return value.get() if value.isDefined() else None


def identifier(value):
    return '"' + value.replace('"', '""') + '"'


def trino_type(data_type):
    name = data_type.typeName()
    scalars = {
        "string": "varchar", "binary": "varbinary", "float": "real",
        "long": "bigint", "short": "smallint", "byte": "tinyint",
        "integer": "integer", "boolean": "boolean", "double": "double",
        "date": "date", "timestamp": "timestamp(3)",
    }
    if name in scalars:
        return scalars[name]
    native_class = data_type.getClass().getSimpleName()
    if native_class == "DecimalType":
        return "decimal(%d,%d)" % (data_type.precision(), data_type.scale())
    if native_class in ("CharType", "VarcharType"):
        return "%s(%d)" % ("char" if native_class == "CharType" else "varchar", data_type.length())
    if name == "array":
        return "array(" + trino_type(data_type.elementType()) + ")"
    if name == "map":
        return "map(" + trino_type(data_type.keyType()) + "," + trino_type(data_type.valueType()) + ")"
    if name == "struct":
        return "row(" + ",".join(identifier(field.name()) + " " + trino_type(field.dataType()) for field in data_type.fields()) + ")"
    raise UnsupportedDDL("Unsupported Athena DDL data type: " + name)


def hive_properties(session, sql, kind):
    # Spark 4 reserves properties such as table_type for its own catalog. Athena
    # uses them as Hive metadata. Retain the original native ANTLR property AST,
    # using Spark's visitor for escaping and validation, not a second SQL grammar.
    jvm = session._jvm
    stream = jvm.org.apache.spark.sql.catalyst.parser.UpperCaseCharStream(
        jvm.org.antlr.v4.runtime.CharStreams.fromString(sql))
    lexer = jvm.org.apache.spark.sql.catalyst.parser.SqlBaseLexer(stream)
    parser = jvm.org.apache.spark.sql.catalyst.parser.SqlBaseParser(
        jvm.org.antlr.v4.runtime.CommonTokenStream(lexer))
    statement = parser.singleStatement().statement()
    if parser.getNumberOfSyntaxErrors() != 0:
        raise UnsupportedDDL("Native Hive property parser rejected the DDL")
    if kind == "CreateNamespace":
        lists = statement.propertyList()
        properties = lists.get(0) if not lists.isEmpty() else None
    else:
        properties = get_field(statement.createTableClauses(), "tableProps")
    if properties is None:
        return {}
    return mapping(session._jsparkSession.sessionState().sqlParser().astBuilder().visitPropertyKeyValues(properties))


def project(session, sql):
    plan = session._jsparkSession.sessionState().sqlParser().parsePlan(sql)
    kind = plan.nodeName()
    if kind == "CreateNamespace":
        native_properties = mapping(plan.properties())
        return {
            "kind": "CREATE_DATABASE", "identifier": sequence(plan.name().multipartIdentifier()),
            "ifNotExists": plan.ifNotExists(), "properties": hive_properties(session, sql, kind),
            "location": native_properties.get("location", ""), "comment": native_properties.get("comment", ""),
        }
    if kind != "CreateTable":
        raise UnsupportedDDL("Unsupported Hive DDL statement: " + kind)
    spec = plan.tableSpec()
    if optional(spec.provider()) is not None:
        raise UnsupportedDDL("Spark USING providers are not Athena Hive DDL")
    if optional(spec.collation()) is not None or not spec.constraints().isEmpty() or not spec.optionExpression().options().isEmpty():
        raise UnsupportedDDL("Spark collation, constraints and OPTIONS are not supported Athena Hive DDL")
    columns = []
    for field in plan.tableSchema().fields():
        metadata = json.loads(field.metadata().json())
        if not field.nullable() or set(metadata) - {"comment"}:
            raise UnsupportedDDL("Column constraints, defaults and generated values require a typed Athena projection")
        columns.append({"name": field.name(), "type": field.dataType().catalogString(),
                        "trinoType": trino_type(field.dataType()), "comment": metadata.get("comment", "")})
    partitions = []
    for transform in sequence(plan.partitioning()):
        references = [list(reference.fieldNames()) for reference in transform.references()]
        if transform.name() != "identity" or len(references) != 1 or len(references[0]) != 1:
            raise UnsupportedDDL("Only identity Hive partition columns are supported")
        partitions.append(references[0][0])
    serde = optional(spec.serde())
    storage_format = optional(serde.storedAs()) if serde else "textfile"
    default = optional(session._jvm.org.apache.spark.sql.internal.HiveSerDe.sourceToSerDe(storage_format or "textfile"))
    if default is None:
        raise UnsupportedDDL("Unsupported Hive storage format: " + str(storage_format))
    input_format, output_format = optional(default.inputFormat()), optional(default.outputFormat())
    serializer = optional(default.serde())
    serde_properties = {}
    if serde:
        formats = optional(serde.formatClasses())
        if formats is not None:
            input_format, output_format = formats.input(), formats.output()
        serializer = optional(serde.serde()) or serializer
        serde_properties = mapping(serde.serdeProperties())
    return {
        "kind": "CREATE_TABLE", "identifier": sequence(plan.name().nameParts()),
        "ifNotExists": plan.ignoreIfExists(), "external": spec.external(),
        "properties": hive_properties(session, sql, kind), "location": str(optional(spec.location()) or ""),
        "comment": str(optional(spec.comment()) or ""), "columns": columns, "partitionColumns": partitions,
        "inputFormat": input_format, "outputFormat": output_format,
        "serde": serializer, "serdeProperties": serde_properties,
    }


session = None
try:
    session = (SparkSession.builder.master("local[1]").appName("stackd-athena-ddl-parser")
               .config("spark.driver.memory", "512m").config("spark.ui.enabled", "false")
               .config("spark.eventLog.enabled", "false")
               .config("spark.sql.legacy.notReserveProperties", "true")
               .config("spark.sql.variable.substitute", "false")
               .config("spark.driver.host", "127.0.0.1").config("spark.sql.catalogImplementation", "in-memory")
               .config("spark.sql.warehouse.dir", "/tmp/athena-parser-warehouse").getOrCreate())
    if session.version != "4.1.3":
        raise RuntimeError("Athena Hive parser requires Apache Spark 4.1.3, received " + session.version)
    sql = base64.b64decode(os.environ.pop("STACKD_HIVE_SQL")).decode("utf-8")
    print(json.dumps({"sparkVersion": session.version, "plan": project(session, sql)}, separators=(",", ":")))
except ParseException as error:
    print(json.dumps({"errorKind": "SYNTAX_ERROR", "error": str(error)}, separators=(",", ":")))
except UnsupportedDDL as error:
    print(json.dumps({"errorKind": "UNSUPPORTED_DDL", "error": str(error)}, separators=(",", ":")))
except Exception as error:
    print(json.dumps({"errorKind": "RUNTIME_ERROR", "error": str(error)}, separators=(",", ":")))
finally:
    if session is not None:
        session.stop()
