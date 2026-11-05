"""Project Apache Spark 4.1.3's Hive DDL AST; never execute SQL or access a catalog."""
import base64
import json
import os

from py4j.java_gateway import get_field
from pyspark.errors import ParseException
from pyspark.sql import SparkSession


class UnsupportedDDL(ValueError):
    """A valid native plan whose Athena metadata projection is unavailable."""


class SyntaxDDL(ValueError):
    """The native ANTLR grammar rejected this statement."""


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


def native_parser(session, sql):
    jvm = session._jvm
    stream = jvm.org.apache.spark.sql.catalyst.parser.UpperCaseCharStream(
        jvm.org.antlr.v4.runtime.CharStreams.fromString(sql))
    lexer = jvm.org.apache.spark.sql.catalyst.parser.SqlBaseLexer(stream)
    tokens = jvm.org.antlr.v4.runtime.CommonTokenStream(lexer)
    parser = jvm.org.apache.spark.sql.catalyst.parser.SqlBaseParser(tokens)
    processor = getattr(jvm.org.apache.spark.sql.catalyst.parser, "PostProcessor$")
    parser.addParseListener(getattr(processor, "MODULE$"))
    return parser, tokens


def native_statement(session, sql):
    # Spark reserves properties Athena retains as Hive metadata. Use the native
    # ANTLR property context and Spark visitor, never a second property grammar.
    parser, _ = native_parser(session, sql)
    statement = parser.singleStatement().statement()
    if parser.getNumberOfSyntaxErrors() != 0:
        raise SyntaxDDL("Native Hive parser rejected the DDL")
    return statement, session._jsparkSession.sessionState().sqlParser().astBuilder()


def hive_properties(session, sql, kind):
    statement, builder = native_statement(session, sql)
    if kind == "CreateNamespace":
        lists = statement.propertyList()
        properties = lists.get(0) if not lists.isEmpty() else None
    else:
        properties = get_field(statement.createTableClauses(), "tableProps")
    if properties is None:
        return {}
    return mapping(builder.visitPropertyKeyValues(properties))


def partition(spec):
    return {"values": mapping(spec.spec()), "location": str(optional(spec.location()) or "")}


def qualified_column(column):
    if optional(column.path()) is not None or not column.nullable() or optional(getattr(column, "default")()) is not None:
        raise UnsupportedDDL("Athena ALTER requires top-level nullable columns without defaults")
    if optional(column.position()) is not None:
        raise UnsupportedDDL("ADD/REPLACE COLUMNS does not support column positions")
    return {"name": column.colName(), "type": column.dataType().catalogString(),
            "trinoType": trino_type(column.dataType()), "comment": str(optional(column.comment()) or ""),
            "commentSet": column.comment().isDefined()}

def partition_column_ddl(session, sql):
    # Athena's optional PARTITION before ADD COLUMNS is absent from Spark's
    # statement alternative. Parse the identifier and partition with the native
    # grammar rules, remove only the native source span, and parse ADD normally.
    parser, tokens = native_parser(session, sql)
    grammar = session._jvm.org.apache.spark.sql.catalyst.parser.SqlBaseParser
    if tokens.LA(1) != grammar.ALTER:
        return None
    tokens.consume()
    if tokens.LA(1) != grammar.TABLE:
        return None
    tokens.consume()
    parser.identifierReference()
    if tokens.LA(1) != grammar.PARTITION:
        return None
    spec = parser.partitionSpec()
    if tokens.LA(1) != grammar.ADD:
        return None
    if parser.getNumberOfSyntaxErrors() != 0:
        raise SyntaxDDL("Native Hive partition parser rejected ALTER")
    builder = session._jsparkSession.sessionState().sqlParser().astBuilder()
    values = mapping(builder.visitNonOptionalPartitionSpec(spec))
    start, end = spec.getStart().getStartIndex(), spec.getStop().getStopIndex()
    result = project(session, sql[:start] + " " + sql[end + 1:])
    if result["kind"] != "ADD_COLUMNS":
        raise UnsupportedDDL("PARTITION before ADD is only supported for ADD COLUMNS")
    result["partitions"] = [{"values": values}]
    return result



def project(session, sql):
    partitioned = partition_column_ddl(session, sql)
    if partitioned is not None:
        return partitioned
    statement, builder = native_statement(session, sql)
    if statement.getClass().getSimpleName() == "HiveReplaceColumnsContext":
        result = {"kind": "REPLACE_COLUMNS",
                  "identifier": sequence(builder.visitMultipartIdentifier(get_field(statement, "table").multipartIdentifier())),
                  "columns": [qualified_column(builder.visitQualifiedColTypeWithPosition(column))
                              for column in get_field(statement, "columns").qualifiedColTypeWithPosition()]}
        if statement.partitionSpec() is not None:
            result["partitions"] = [{"values": mapping(builder.visitNonOptionalPartitionSpec(statement.partitionSpec()))}]
        return result
    # Spark deliberately rejects CHANGE old new when the names differ. The
    # native Hive ANTLR context retains Athena's valid rename grammar; project
    # that context through Spark's own typed datatype/identifier visitors.
    if statement.getClass().getSimpleName() == "HiveChangeColumnContext":
        old = sequence(builder.visitMultipartIdentifier(get_field(statement, "colName")))
        if len(old) != 1:
            raise UnsupportedDDL("Athena CHANGE requires a top-level column")
        definition = statement.colType()
        column = builder.visitColType(definition)
        if not column.nullable():
            raise UnsupportedDDL("Athena CHANGE does not support NOT NULL")
        datatype = column.dataType()
        result = {"kind": "CHANGE_COLUMN",
                  "identifier": sequence(builder.visitMultipartIdentifier(get_field(statement, "table").multipartIdentifier())),
                  "oldColumn": old[0],
                  "columns": [{"name": column.name(),
                               "type": datatype.catalogString(), "trinoType": trino_type(datatype),
                               "comment": str(builder.visitCommentSpec(definition.commentSpec())) if definition.commentSpec() else "",
                               "commentSet": definition.commentSpec() is not None}]}
        position = statement.colPosition()
        if position:
            native_position = builder.visitColPosition(position)
            if native_position.getClass().getSimpleName() == "First":
                result["first"] = True
            else:
                result["afterColumn"] = native_position.column()
        if statement.partitionSpec() is not None:
            raise UnsupportedDDL("Athena CHANGE does not accept PARTITION")
        return result
    plan = session._jsparkSession.sessionState().sqlParser().parsePlan(sql)
    kind = plan.nodeName()
    if kind == "CreateNamespace":
        native_properties = mapping(plan.properties())
        return {
            "kind": "CREATE_DATABASE", "identifier": sequence(plan.name().multipartIdentifier()),
            "ifNotExists": plan.ifNotExists(), "properties": hive_properties(session, sql, kind),
            "location": native_properties.get("location", ""), "comment": native_properties.get("comment", ""),
        }
    if kind == "DropNamespace":
        return {
            "kind": "DROP_DATABASE", "identifier": sequence(plan.namespace().multipartIdentifier()),
            "ifExists": plan.ifExists(), "cascade": plan.cascade(),
        }
    if kind == "SetNamespaceProperties":
        return {"kind": "SET_DATABASE_PROPERTIES", "identifier": sequence(plan.namespace().multipartIdentifier()),
                "properties": mapping(plan.properties())}
    if kind in ("AddColumns", "ReplaceColumns", "SetTableProperties", "SetTableLocation",
                "AddPartitions", "DropPartitions", "RenamePartitions", "RepairTable"):
        result = {"identifier": sequence(plan.child().multipartIdentifier())}
        if kind in ("AddColumns", "ReplaceColumns"):
            result.update(kind="ADD_COLUMNS" if kind == "AddColumns" else "REPLACE_COLUMNS",
                          columns=[qualified_column(column) for column in sequence(plan.columnsToAdd())])
        elif kind == "SetTableProperties":
            result.update(kind="SET_TABLE_PROPERTIES", properties=mapping(plan.properties()))
        elif kind == "SetTableLocation":
            spec = optional(plan.partitionSpec())
            result.update(kind="SET_LOCATION", location=plan.location(),
                          partitions=[{"values": mapping(spec)}] if spec is not None else [])
        elif kind == "AddPartitions":
            result.update(kind="ADD_PARTITIONS", ifNotExists=plan.ifNotExists(),
                          partitions=[partition(spec) for spec in sequence(plan.parts())])
        elif kind == "DropPartitions":
            if plan.purge():
                raise UnsupportedDDL("Athena external partition DROP does not accept PURGE")
            result.update(kind="DROP_PARTITIONS", ifExists=plan.ifExists(),
                          partitions=[partition(spec) for spec in sequence(plan.parts())])
        elif kind == "RenamePartitions":
            result.update(kind="RENAME_PARTITION", partitions=[partition(getattr(plan, "from")())],
                          newPartition=mapping(plan.to().spec()))
        else:
            if not plan.enableAddPartitions() or plan.enableDropPartitions():
                raise UnsupportedDDL("Athena MSCK only supports adding discovered partitions")
            result.update(kind="MSCK_REPAIR")
        return result
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
    partitions, transforms = [], []
    bucket_count, bucket_columns = 0, []
    iceberg = hive_properties(session, sql, kind).get("table_type", "").upper() == "ICEBERG"
    for transform in sequence(plan.partitioning()):
        references = [list(reference.fieldNames()) for reference in transform.references()]
        if any(len(reference) != 1 for reference in references):
            raise UnsupportedDDL("Partition transforms require top-level columns")
        fields = [reference[0] for reference in references]
        name = transform.name()
        if name == "identity":
            partitions.extend(fields)
        elif name in ("bucket", "sorted_bucket") and not iceberg:
            arguments = list(transform.arguments())
            bucket_count = int(arguments[0].value())
            if name == "sorted_bucket":
                raise UnsupportedDDL("SORTED BY requires a native sort-order projection")
            bucket_columns = fields
            continue
        elif not iceberg or name not in ("bucket", "truncate", "years", "months", "days", "hours", "year", "month", "day", "hour"):
            raise UnsupportedDDL("Unsupported Athena partition transform: " + name)
        count = int(list(transform.arguments())[0].value()) if name in ("bucket", "truncate") else 0
        transforms.append({"name": name, "fields": fields, "count": count})
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
        "bucketCount": bucket_count, "bucketColumns": bucket_columns,
        "partitionTransforms": transforms,
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
except (ParseException, SyntaxDDL) as error:
    print(json.dumps({"errorKind": "SYNTAX_ERROR", "error": str(error)}, separators=(",", ":")))
except UnsupportedDDL as error:
    print(json.dumps({"errorKind": "UNSUPPORTED_DDL", "error": str(error)}, separators=(",", ":")))
except Exception as error:
    print(json.dumps({"errorKind": "RUNTIME_ERROR", "error": str(error)}, separators=(",", ":")))
finally:
    if session is not None:
        session.stop()
