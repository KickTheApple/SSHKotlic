<script setup lang="ts">
import { ref } from 'vue'
import axios from "axios";
import router from "@/router";
import {onMounted} from "vue";
import {list} from "postcss";
import MovingMenu from "@/views/MovingMenu.vue";
import Pathway from "@/views/Pathway.vue";

interface log_format {
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

let log_list = ref<log_format[]>([]);
let total_session_count = ref<Number>(0);
let analysis_target = ref<log_format>();
let active_attacks = ref(0);
let recent_session = ref<log_format>(null);

let loading_state = ref(true)

async function fetchData(): Promise<Array<any>> {
  let foundLog = []

  try {
    const response_total = await axios.get("/api/logs/");
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

function getActiveSessionCount(logs: Array<log_format>): number {
  let count = 0;
  for (let log of logs) {
    if (log.activity) {
      count++;
    }
  }
  return count;
}

function getMostRecentSession(logs: Array<log_format>): log_format {
  let mostRecentTime = 0
  let mostRecentSession = null
  for (let log of logs) {
    let currentSessionTime = Date.parse(log.event_time);
    if (mostRecentTime < currentSessionTime) {
      mostRecentTime = currentSessionTime;
      mostRecentSession = log;
    }
  }
  console.log(mostRecentSession)
  return mostRecentSession;
}

function redirectToRecentSession(log: log_format) {
  if (log === null) {
    return
  }
  router.push({ name: "analysis", params: {sessionID: log } });
}

onMounted(async () => {
  log_list.value = await fetchData() ?? []
  active_attacks.value = getActiveSessionCount(log_list.value)
  recent_session.value = getMostRecentSession(log_list.value)
})

</script>

<template>
  <MovingMenu />
  <Pathway />
  <div class="dashboard-overview">
    <div class="dashbaord-card">
      <h2>Total session count: {{ log_list.length }}</h2>
    </div>
    <div class="dashbaord-card">
      <h2>Current Active attacks are {{ active_attacks }}</h2>
    </div>
    <div class="dashbaord-card">
      <h2>Most recent session is {{ recent_session?.session_id ?? "None" }}</h2>
    </div>
  </div>
</template>

<style scoped>
body {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}

.dashboard-overview {
  display: flex;
  gap: 1rem;
  padding: 1rem;
  align-items: center;
}

.dashbaord-card {
  border-radius: 25px;
  border: 2px solid #cccccc;
  padding: 20px;
  width: 200px;
  height: 150px;
}
</style>
