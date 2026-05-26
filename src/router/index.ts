import { createRouter, createWebHistory } from "vue-router";
import axios from "axios";
import Dashboard from '@/views/Dashboard.vue';
import Signin from "../views/Signin.vue";
import Analysis from "../views/Analysis.vue";
import Logs from "../views/Logs.vue";
import Statistics from "../views/Statistics.vue";

const routes = [
    {
        path: "/sign-in",
        name: "sign-in",
        component: Signin,
    },
    {
        path: "/",
        redirect: "/sign-in",
    },

    {
        path: "/dashboard",
        name: "dashboard",
        component: Dashboard,
    },
    {
        path: "/statistics",
        name: "statistics",
        component: Statistics,
    },
    {
        path: "/logs",
        name: "logs",
        component: Logs,
    },
    {
        path: "/logs/:sessionID",
        name: "analysis",
        component: Analysis,
    },

];
const router = createRouter({
    history: createWebHistory(),
    routes,
});

const guard = function(to, from, next) {
    if (to.path == "/" || to.path == "/sign-in" ||  to.path == "/sign-up") {
        next();
    } else {
        axios.post('/api/auth/sign-in').then(response => {
            next();
        }).catch(error => {
            window.location.href = "/sign-in"
        })
    }
};

//router.beforeEach()

export default router;