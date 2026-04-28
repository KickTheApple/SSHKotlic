from django_opensearch_dsl import Document, fields
from django_opensearch_dsl.registries import registry

from datapot.models import LogModel


@registry.register_document
class PoticaDocument(Document):

    timestamp = fields.DateField()
    event_name = fields.KeywordField()
    event_time = fields.DateField()
    start_time = fields.DateField()
    session_id = fields.KeywordField()
    src_ip = fields.KeywordField()
    src_port = fields.IntegerField()
    container_id = fields.KeywordField()
    username = fields.KeywordField()
    password = fields.KeywordField()

    class Index:
        name = "potica"
        auto_refresh = False

    class Django:
        model = LogModel

@registry.register_document
class BashDocument(Document):

    timestamp = fields.DateField(source="@timestamp")
    event_name = fields.KeywordField()
    event_time = fields.DateField()
    container_id = fields.KeywordField()
    session_id = fields.KeywordField()
    bash_data = fields.KeywordField()

    class Index:
        name = "bash"
        auto_refresh = False

    class Django:
        model = LogModel