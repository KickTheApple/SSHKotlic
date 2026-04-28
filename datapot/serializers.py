from rest_framework import serializers

class LogSerializer(serializers.Serializer):
    timestamp = serializers.DateTimeField(source="@timestamp")
    event_name = serializers.CharField()
    event_time = serializers.DateTimeField()
    start_time = serializers.DateTimeField()
    session_id = serializers.CharField()
    src_ip = serializers.CharField()
    src_port = serializers.IntegerField()
    container_id = serializers.CharField(required=False)
    username = serializers.CharField(required=False)
    password = serializers.CharField(required=False)

class BashSerializer(serializers.Serializer):
    timestamp = serializers.DateTimeField(source="@timestamp")
    event_name = serializers.CharField()
    event_time = serializers.DateTimeField()
    container_id = serializers.CharField()
    session_id = serializers.CharField()
    bash_data = serializers.CharField()