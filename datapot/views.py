import json
import os.path
import string
from datetime import datetime, timezone

from django_opensearch_dsl.search import Search
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_200_OK
from rest_framework.views import APIView
from rest_framework.response import Response
from scapy.utils import PcapReader

from datapot.documents import PoticaDocument
from datapot.documents import BashDocument
from datapot.serializers import LogSerializer, BashSerializer

from .forms import UploadFileForm
from scapy.layers.inet import IP, TCP

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

def get_repeat_list(response):
    repeat_set = set()
    for hit in response:
        if "session_id" not in response:
            continue
        sesh_id = hit["session_id"]
        search: Search = PoticaDocument.search()
        search = search.filter("term", session_id=sesh_id)
        search = search.filter("term", event_name="sign_in_repeat")
        if search.count() > 0:
            repeat_set.add(sesh_id)
    return list(repeat_set)


def get_bash_list(response):
    bash_set = set()
    for hit in response:
        if "session_id" not in hit:
            continue
        sesh_id = hit["session_id"]
        search: Search = BashDocument.search()
        search = search.filter("term", session_id=sesh_id)
        if search.count() > 0:
            bash_set.add(sesh_id)
    return list(bash_set)

def get_active_list(response):
    active_set = set()
    for hit in response:
        if "session_id" not in hit:
            continue
        sesh_id = hit["session_id"]
        search: Search = PoticaDocument.search()
        search = search.filter("term", session_id=sesh_id)
        search = search.filter("term", event_name="connection_end")
        if search.count() == 0:
            active_set.add(sesh_id)
    return list(active_set)

def hit_handling(response):
    active_list = get_active_list(response)
    bash_list = get_bash_list(response)

    for hit in response:
        hit["active_state"] = hit["session_id"] in active_list
        hit["bash_state"] = hit["session_id"] in bash_list

    response.sort(key=lambda x: x["event_time"])

    return response

class PcapView(APIView):
    #permission_classes = [IsAuthenticated]

    def get(self, request: Request):
        if not request.user.is_authenticated:
            return Response({"status": "no auth"}, status=HTTP_401_UNAUTHORIZED)

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
    #permission_classes = [IsAuthenticated]

    def get(self, request: Request):
     #   if not request.user.is_authenticated:
      #      return Response({"status": "no auth"}, status=HTTP_401_UNAUTHORIZED)

        query_info = request.query_params
        if "session_id" not in query_info:
            return Response({
                "status": "failure"
            })
        sesh_id = query_info.get("session_id")

        search: Search = BashDocument.search()
        search = search.filter("term", session_id=sesh_id)

        response: list = list(search.scan())
        response.sort(key=lambda x: x["event_time"])

        serializer = BashSerializer(
            [hit.to_dict() for hit in response],
            many=True
        )

        return Response({
            "count": len(serializer.data),
            "results": serializer.data
        })

class SessionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request):
        query_info = request.query_params
        if "session_id" not in query_info:
            return Response({"status": "failure"})
        sesh_id = query_info.get("session_id")

        search: Search = PoticaDocument.search()
        search = search.filter("term", session_id=sesh_id)

        response: list = list(search.scan())
        response = hit_handling(response)

        serializer = LogSerializer(
            response,
            many=True
        )

        return Response({
            "count": len(serializer.data),
            "results": serializer.data
        })

class SessionCredView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request):
        if not request.user.is_authenticated:
            return Response({"status": "no auth"}, status=HTTP_401_UNAUTHORIZED)

        query_info = request.query_params
        if "session_id" not in query_info:
            return Response({"status": "failure"})

        sesh_id = query_info.get("session_id")
        search: Search = PoticaDocument.search()
        search = search.filter("term", session_id=sesh_id)
        search = search.filter("terms", event_name=["connection_end", "auth_failure", "auth_success"])

        response = list(search.scan())

        username = ""
        password_list = list()
        for hit in response:
            if hit["event_name"] == "connection_end":
                username = hit["username"]
            elif hit["event_name"] == "auth_failure":
                username = hit["username"]
                password_list.append(hit["password"])
            else:
                username = hit["username"]
                password_list.append(hit["password"])

        return Response({
            "attempts": len(password_list),
            "username": username,
            "password": password_list
        }, HTTP_200_OK)



class LogsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request):
        if not request.user.is_authenticated:
            return Response({"status": "no auth"}, status=HTTP_401_UNAUTHORIZED)

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

        search = search.filter("term", event_name="connection_start")
        response: list = list(search.scan())
        response = hit_handling(response)

        serializer = LogSerializer(
            response,
            many=True
        )

        return Response({
            "count": len(serializer.data),
            "results": serializer.data
        })


class LogCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request):
        if not request.user.is_authenticated:
            return Response({"status": "no_auth"}, status=HTTP_401_UNAUTHORIZED)

        search: Search = PoticaDocument.search()
        search = search.filter("term", event_name="connection_start")

        response = search.count()

        return Response({"count": response}, status=HTTP_200_OK)


class LogActiveView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request):
        if not request.user.is_authenticated:
            return Response({"status": "no_auth"}, status=HTTP_401_UNAUTHORIZED)

        searchStart: Search = PoticaDocument.search()
        searchStart = searchStart.filter("term", event_name="connection_start")

        searchEnd: Search = PoticaDocument.search()
        searchEnd = searchEnd.filter("term", event_name="connection_end")
        endings = list(searchEnd.scan())
        invalidSessions = list(set(sessioning["session_id"] for sessioning in endings if "session_id" in sessioning))

        searchStart = searchStart.exclude("terms", session_id=invalidSessions)
        response = searchStart.count()
        print([foundSession["session_id"] for foundSession in list(searchStart.scan())])



        return Response({"count": response}, status=HTTP_200_OK)

class LogRecentView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request):
        if not request.user.is_authenticated:
            return Response({"status": "no_auth"}, status=HTTP_401_UNAUTHORIZED)

        search: Search = PoticaDocument.search()
        search = search.filter("term", event_name="connection_start")
        response = list(search[0:1].execute())

        if len(response) > 0 and "session_id" in response[0]:
            response = hit_handling(response)

        serializer: LogSerializer = LogSerializer(
            response,
            many=True
        )

        return Response({
            "count": len(serializer.data),
            "results": serializer.data
        }, status=HTTP_200_OK)
