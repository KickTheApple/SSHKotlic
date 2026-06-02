<script setup lang="ts">
import { ref } from 'vue'
import axios from "axios";
import router from "@/router";
import {onMounted} from "vue";
import {list} from "postcss";
import MovingMenu from "@/views/MovingMenu.vue";
import Pathway from "@/views/Pathway.vue";

const menuData = ref([
  {
    label: "Home",
    icon: 'pi pi-home'
  }
]);

export interface log_format {
  "event_name": string,
  "event_time": string,
  "start_time": string,
  "session_id": string,
  "src_ip": string,
  "src_port": Number,
  "container_id": string,
  "username": string,
  "password": string,
  "activity": boolean,
}

interface hittingData {
  "count": Number,
  "results": Array<log_format>
}

let log_list = ref<log_format[]>([])
let analysis_target = ref<log_format>()

let loading_state = ref(true)

async function fetchData(): Promise<Array<any>> {
  let foundLog = []

  try {
    const response_total = await axios.get("/api/logs/sessions");
    const response_hits: hittingData = response_total.data;
    response_hits.results.forEach((responder: log_format) => {
      foundLog.push(responder)
    })
    loading_state.value = false;
  } catch {
    router.push("/sign-in");
  }
  return foundLog;
}

function analyseData() {
  let selected_log: log_format = analysis_target.value;
  console.log(selected_log);
  if (analysis_target == null) {
    return;
  }
  router.push({ name: "analysis", params: {sessionID: selected_log.session_id} })
}

onMounted(async () => {
  log_list.value = await fetchData() ?? []
})
</script>

<template>
  <MovingMenu />
  <Pathway />
  <DataTable :value="log_list" v-model:selection="analysis_target" selectionMode="single" @row-select="analyseData" :metaKeySelection="true" :loading="loading_state" tableStyle="min-width: 50rem">
    <Column field="session_id" header="Session_id"></Column>
    <Column field="event_time" header="Event_time"></Column>
    <Column field="start_time" header="Start_time"></Column>
    <Column field="src_ip" header="Src_ip"></Column>
    <Column field="src_port" header="Src_port"></Column>
  </DataTable>
</template>

<style scoped>

</style>