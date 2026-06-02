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
let analysis_target = ref<log_format>(null);
let active_attacks = ref(0);
let recent_session = ref<log_format>(null);

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
  let selected_log: log_format = analysis_target?.value;
  if (analysis_target == null) {
    return;
  }
  router.push({ name: "analysis", params: {sessionID: selected_log.session_id} })
}

async function getTotalSessionCount(): Promise<number> {
  try {
    let response = await axios.get("/api/logs/total_count");
    return response.data.count;
  } catch {
    return 0;
  }
}

async function getActiveSessionCount(): Promise<number> {
  try {
    let response = await axios.get("/api/logs/active_count");
    return response.data.count;
  } catch {
    return 0;
  }
}

async function getMostRecentSession(): Promise<log_format> {
  try {
    let response = await axios.get("/api/logs/recent");
    if (response.data.count == 1) {
      return response.data.results[0]
    }
    return;
  } catch {
    return;
  }
}

function redirectToRecentSession(log: log_format) {
  if (log === null) {
    return
  }
  router.push({ name: "analysis", params: {sessionID: log } });
}

onMounted(async () => {
  log_list.value = await fetchData() ?? []
  total_session_count.value = await getTotalSessionCount();
  active_attacks.value = await getActiveSessionCount();
  recent_session.value = await getMostRecentSession();
})

</script>

<template>
  <MovingMenu />

  <div class="dashboard-overview">
    <div class="dashbaord-card">
      <h2>Total session count: {{ total_session_count }}</h2>
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
