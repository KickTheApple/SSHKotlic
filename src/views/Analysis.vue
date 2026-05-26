<script setup>
import axios from "axios";
import router from "../router/index.ts"
import MovingMenu from "@/views/MovingMenu.vue";
import {ref} from "vue";
import Pathway from "@/views/Pathway.vue";

let sessionID = router.currentRoute.value.params.sessionID;

</script>

<template>
  <MovingMenu />
  <div class="analysis-container">
    <div class="card flex justify-center">
      <Pathway />
    </div>

  </div>
</template>

<style scoped>

</style>