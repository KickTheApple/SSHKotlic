import './assets/main.css';
import { createApp } from 'vue';
import axios from "axios";
import router from './router/index'
import PrimeVue from 'primevue/config';
import Aura from '@primeuix/themes/aura';
import Ripple from 'primevue/ripple';
import 'primeicons/primeicons.css';
import App from "./views/App.vue";

axios.interceptors.request.use((config) => {
    const token = document.cookie
        .split('; ')
        .find(row => row.startsWith('csrftoken='))
        ?.split('=')[1];

    if (token) {
        config.headers['X-CSRFToken'] = token;
    }
    return config;
});



const app = createApp(App);
app.use(PrimeVue, {
    theme: {
        preset: Aura,
        options: {
            prefix: 'p',
            darkModeSelector: false,
            cssLayer: false
        }
    }
});

app.directive('ripple', Ripple);
app.use(router)
app.mount('#app');
