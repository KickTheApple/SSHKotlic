<script setup lang="ts">
import {onMounted, ref} from "vue";
import router from "@/router";
import axios from "axios";

const props = defineProps({
  bash_logs: Array<bash_format>,
  bash_string: String
})

let barPosition = ref<number>(50)
let currentLog = ref<number>(0)

function rebuild_console_out(timestamp: number) {
  Date.parse

}

function skidadle(data: MouseEvent) {
  const rect = (data.currentTarget as HTMLDivElement).getBoundingClientRect();
  const width = rect.width;

  barPosition.value = (data.layerX / width) * 100;

}

export interface bash_format {
  event_name: string,
  event_time: string,
  container_id: string,
  session_id: string,
  bash_data: string,
}


function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

</script>

<template>
  <div class="playback-container">
    <div class="timehead-container">
      <ProgressBar :value="barPosition" :onclick="skidadle"></ProgressBar>
    </div>
    <div class="writehead-container">
      <pre>{{ bash_string }}</pre>
    </div>
  </div>
</template>

<style scoped>
.playback-container {
  border-radius: 10px;
  border: 2px solid #c0c0c0;
  padding: 10px;
  margin-top: 10px;
}

.timehead-container {

}

.writehead-container {
  background-color: #efefef;
  min-height: 500px;
}
</style>