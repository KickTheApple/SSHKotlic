import json
import os.path
from datetime import datetime, timezone
from http.client import responses
from django_opensearch_dsl import Document
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django_opensearch_dsl.search import Search
from requests import session
from rest_framework.request import Request
from rest_framework.views import APIView
from rest_framework.response import Response
from scapy.layers.l2 import CookedLinux
from scapy.utils import PcapReader

from datapot.documents import PoticaDocument
from datapot.documents import BashDocument
from datapot.serializers import LogSerializer, BashSerializer

from django.shortcuts import render
from .forms import UploadFileForm
from scapy.layers.inet import IP, TCP
import scapy


# Create your views here.

class SearchParams:
    startTime: str | None
    endTime: str | None
    src_ip: str | None
    username: str | None
    password: str | None
    session_id: str | None
    container_id: str | None
    minDuration: str | None
    maxDuration: str | None
    
    def __init__(self):
        self.startTime = None
        self.endTime = None
        self.src_ip = None
        self.username = None
        self.password = None
        self.session_id = None
        self.container_id = None
        self.minDuration = None
        self.maxDuration = None

    def active_paramters(self):
        chosen_ones = dict()
        for param in self.__dict__.keys():
            if self.__dict__[param] is not None:
                chosen_ones[param] = self.__dict__[param]
        return chosen_ones

class PcapView(APIView):
    def get(self, request: Request):
        query_info = request.query_params
        if "session_id" not in query_info:
            return Response({
                "status": "failure"
            })
        sesh_id = query_info.get("session_id")

        filename = f'pcap_data/{sesh_id}.txt'
        if not os.path.isfile(filename):
            return Response({
                "status": "failure"
            })

        with open(filename, "r") as file:
            paketki = file.read()
            paket_list = paketki.split("\n")[:-1]
            print(paket_list)

        paket_packed = [json.loads(paket) for paket in paket_list]

        return Response({
            "count": len(paket_packed),
            "results": paket_packed
        })

    def post(self, request: Request):
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            print(file)

            identifier = request.POST.get("title")
            filename_pcap = f'pcap_data/{identifier}.pcap'
            with open(filename_pcap, "wb") as pcap_file:
                for chunk in file.chunks():
                    pcap_file.write(chunk)

            paketki = PcapReader(filename_pcap)
            filename_json = f'pcap_data/{identifier}.txt'
            with open(filename_json, 'w') as json_file:
                for paket in paketki:
                    raw = bytes(paket)
                    ip_packet = IP(raw[16:])
                    if ip_packet.haslayer(TCP):
                        tcp = ip_packet[TCP]
                        timestamp = datetime.fromtimestamp(float(paket.time))
                        json_str = json.dumps({"time": timestamp.isoformat(), "srcIp": ip_packet.src, "port": tcp.sport, "dstIp": ip_packet.dst})
                        print(json_str)
                        json_file.write(f'{json_str}\n')

            if os.path.isfile(filename_pcap):
                os.remove(filename_pcap)

            return Response({"status": "success"}, status=201)
        return Response({"status": "failure", "errors": form.errors}, status=400)

class BashView(APIView):
    def get(self, request: Request):
        query_info = request.query_params
        if "session_id" not in query_info:
            return Response({
                "status": "failure"
            })
        sesh_id = query_info.get("session_id")

        search: Search = BashDocument.search()
        search = search.filter("term", session_id=sesh_id)

        response: list = list(search.scan())

        serializer = BashSerializer(
            [hit.to_dict() for hit in response],
            many=True
        )

        return Response({
            "count": len(serializer.data),
            "results": serializer.data
        })

class SessionView(APIView):
    def get(self, request: Request):
        query_info = request.query_params
        if "session_id" not in query_info:
            return Response({
                "status": "failure"
            })
        sesh_id = query_info.get("session_id")

        search: Search = PoticaDocument.search()
        search = search.filter("term", session_id=sesh_id)

        response: list = list(search.scan())

        serializer = LogSerializer(
            [hit.to_dict() for hit in response],
            many=True
        )

        return Response({
            "count": len(serializer.data),
            "results": serializer.data
        })

class LogsView(APIView):
    def get(self, request: Request):
        query_info = request.query_params
        print(query_info)

        search_parameters: SearchParams = SearchParams()

        if "startTime" in query_info:
            search_parameters.startTime = query_info.get("startTime")
        if "endTime" in query_info:
            search_parameters.endTime = query_info.get("endTime")
        if "src_ip" in query_info:
            search_parameters.src_ip = query_info.get("src_ip")
        if "session_id" in query_info:
            search_parameters.session_id = query_info.get("session_id")
        if "container_id" in query_info:
            search_parameters.container_id = query_info.get("container_id")
        if "username" in query_info:
            search_parameters.username = query_info.get("username")
        if "password" in query_info:
            search_parameters.password = query_info.get("password")

        active_ones = search_parameters.active_paramters()
        search: Search = PoticaDocument.search()
        for activity in active_ones:
            if activity == "startTime":
                search = search.filter("range", timestamp={"gte":active_ones[activity]})
            elif activity == "endTime":
                search = search.filter("range", timestamp={"lte":active_ones[activity]})
            else:
                search = search.filter("term", **{activity: active_ones[activity]})

        response: list = list(search.scan())

        session_set = []
        for hit in response:
            sesh_id = hit["session_id"]
            if sesh_id not in session_set:
                session_set.append(sesh_id)

        search = PoticaDocument.search()
        search = search.filter("terms", session_id=session_set)
        search = search.filter("term", event_name="connection_start")

        response = list(search.scan())

        serializer = LogSerializer(
            [hit.to_dict() for hit in response],
            many=True
        )

        return Response({
            "count": len(serializer.data),
            "results" :serializer.data
        })