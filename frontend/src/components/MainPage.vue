<template>
  <div>
    <input type="text" v-model="message" />
    <button @click="signMessage">Sign message</button>
    <div v-if="hash.length">Hash: {{ hash }}</div>
    <div v-if="hash.length">
      <input type="text" v-model="link" disabled />
      <div>
        <iframe v-bind:src="link" height="100%" width="100%"></iframe>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      hash: "",
      message: "",
    };
  },

  computed: {
    link() {
      return `http://127.0.0.1:8080/ipfs/${this.hash}/data/`;
    },
  },

  methods: {
    async signMessage() {
      const response = await fetch(
        import.meta.env.VITE_API_ENDPOINT + "/sign",
        {
          method: "POST",
          headers: {
            Accept: "application.json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ msg: this.message }),
          cache: "default",
        }
      );
      const response_data = await response.json();
      this.hash = response_data.hash[response_data.hash.length - 1];
    },
  },
  setup() {},
};
</script>

<style scoped>
input {
  width: 90%;
}
iframe {
  width: 100%;
  height: 100%;
}
button {
  float: right;
}
</style>
