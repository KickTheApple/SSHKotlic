<script setup lang="ts">
import axios from "axios";
import router from "@/router"
import MovingMenu from "@/views/MovingMenu.vue";
import {onMounted, ref} from "vue";
import {log_format} from "@/views/Logs.vue"
import Pathway from "@/views/Pathway.vue";
import BashPlayback from "@/views/BashPlayback.vue";

export interface bash_format {
  event_name: string,
  event_time: string,
  container_id: string,
  session_id: string,
  bash_data: string,
}

interface bashingData {
  "count": Number,
  "results": Array<bash_format>
}

let sessionID = router.currentRoute.value.params.sessionID;
let bashContent = ref<Array<bash_format>>();
let bashVisualizer = ref<string>("");

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function getSessionInfo(): Promise<Array<log_format>> {
  try {
    let response = await axios.get("/api/session/", {params: {session_id: sessionID}});
    console.log(response.data);
  } catch {
    console.log("Error: couldn't get SessionInfo");
    //router.push({name: "sign-in"});
  }
}

async function getAllBashLogs(): Promise<Array<bash_format>> {
  try {
    let reqeuest = await axios.get("/api/bash/", { params: {session_id: sessionID}});
    let response: bashingData = reqeuest.data;
    console.log(response);

    let bashdata: Array<bash_format> = response.results;
    bashdata.sort((data)=>{return Date.parse(data.event_time)}).reverse();
    return bashdata;

  } catch {
    router.push({name: "sign-in"});
  }
}

async function playback() {
  console.log("START")
  bashVisualizer.value = "";
  if (bashContent.value.length == 0) {
    return;
  }

  let startTime = Date.parse(bashContent.value[0].event_time);
  let endTime = Date.parse(bashContent.value[bashContent.value.length-1].event_time);
  let duration = endTime - startTime
  let timer = 0;

  for (let i = 0; i < bashContent.value.length; i++) {
    let currentBash = bashContent.value[i];
    let nextBash = bashContent.value[Math.min(i+1, bashContent.value.length-1)];

    let value = atob(currentBash.bash_data);
    bashVisualizer.value += value;
    console.log(value)
    await sleep(Date.parse(nextBash.event_time) - Date.parse(currentBash.event_time))
  }
}

onMounted(async () => {
  bashContent.value = await getAllBashLogs();
  getSessionInfo();
})

</script>

<template>
  <MovingMenu />
  <Pathway />
  <div class="static-data">

  </div>
  <Button label="Clickme" :onClick="playback"/>
  <BashPlayback :bash_logs="bashContent" :bash_string="bashVisualizer" />
</template>

<style scoped>

</style>