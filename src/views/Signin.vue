<script setup>
import axios from "axios";
import router from "@/router/index.ts";
import Dashboard from "@/views/Dashboard.vue";

async function loggerton({ values }) {
  console.log(values)

  const response = await axios.post("/api/auth/sign-in", {
    username: values.username,
    password: values.password
  });

  if (response.status === 200) {
    router.push("/dashboard")
  }
  console.log(response)
}
</script>

<template>
  <body>
    <div id="auth-form">
      <Form v-slot="values" @submit="loggerton" class="flex justify-center flex-col gap-4">
        <div class="flex flex-col gap-1">
          <InputText id="on_label" name="username" type="text" placeholder="Username" />
          <Message v-if="values.username?.invalid" severity="error" size="small" variant="simple">{{ $form.username.error?.message }}</Message>
        </div>
        <div class="flex flex-col gap-1">
          <InputText id="on_label" name="password" type="text" placeholder="password" />
          <Message v-if="values.password?.invalid" severity="error" size="small" variant="simple">{{ $form.password.error?.message }}</Message>
        </div>
        <Button type="submit" severity="secondary" label="Submit" />
      </Form>
    </div>
  </body>
</template>

<style scoped>

</style>