<script setup lang="ts">
import router from "../router/index.ts"
import {ref} from "vue";

let segmentedPath = router.currentRoute.value.fullPath.split("/")

console.log(segmentedPath)

const home = ref({
  icon: "pi pi-home",
})

const items = ref(segmentedPath.filter(
    (segment) => (segment !== "")).map(
    (segment) => ({label: segment.charAt(0).toUpperCase() + segment.slice(1), command: () => {router.push({name: segment})}})
))

</script>

<template>
  <div class="card flex justify-center">
    <Breadcrumb :home="home" :model="items"/>
  </div>
</template>

<style scoped>

</style>