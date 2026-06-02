<script setup lang="ts">
import {ref} from "vue";
import router from "@/router/index.ts";

function redirectTo(pathName: string) {
  return () => {
    router.push({ name: pathName})
  }
}

const menuData = ref([
  {
    label: "Dashboard",
    icon: 'pi pi-objects-column',
    command: redirectTo("dashboard"),
  },
  {
    label: "Statistics",
    icon: "pi pi-chart-bar",
    command: redirectTo("statistics"),
  },
  {
    label: "Logs",
    icon: "pi pi-list",
    command: redirectTo("logs"),
  },
]);

</script>

<template>
  <Menubar :model="menuData" class="p-menubar"/>
</template>

<style scoped>
.p-menubar {
  width: 100%;
}
</style>