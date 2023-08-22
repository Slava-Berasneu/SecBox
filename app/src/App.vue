<template>

  <v-app class="bg-grey-darken-4">
    <v-app-bar
      fixed
      color="deep-purple darken-2"
      dark
      prominent
    >
<router-link to="/">
      <v-btn icon color="white">

          <v-icon >mdi-home</v-icon>

      </v-btn>
  </router-link>

      <router-link to="/reports">

      <v-btn icon color="white">
        <v-icon >mdi-view-dashboard</v-icon>
      </v-btn>
      </router-link>

      <StartAnalysisDialog :oss="this.osData" :malwares="this.mwData" :syscallAnalyzerModels="this.syscallAnalyzerModels" 
      :performanceAnalyzerModels="this.performanceAnalyzerModels" :syscallDetectorModels="this.syscallDetectorModels" 
      :performanceDetectorModels="this.performanceDetectorModels"/>

      <v-app-bar-title>
        <p>{{ greeting }} - {{ flaskGreeting }}</p>
         <p></p>
      </v-app-bar-title>

      <v-spacer></v-spacer>

    </v-app-bar>

    <v-main>
      <router-view />
    </v-main>
  </v-app>

</template>

<style>
v-app {
  color: darkslategrey;
}
a { text-decoration: none; }

</style>

<script>
import StartAnalysisDialog from "@/components/StartAnalysisDialog";

export default {
  name: 'App',
  components: {
    StartAnalysisDialog,

  },

  data: () => ({
      greeting: 'SecBox',
      flaskGreeting: '',
    osData:[],
    mwData:[],
    syscallAnalyzerModels:[],
    performanceAnalyzerModels:[],
    syscallDetectorModels:[],
    performanceDetectorModels:[]
  }),
  created: async function(){
      const gResponse = await fetch("http://"+process.env.VUE_APP_ROOT+"/greeting");
      const gObject = await gResponse.json();
      this.flaskGreeting = gObject.greeting;

      const startData = await fetch("http://"+process.env.VUE_APP_ROOT+"/getStartData");
      const startObj = await startData.json();
      this.osData = JSON.parse(startObj.oss)
      this.mwData = JSON.parse(startObj.malwares)
      this.syscallAnalyzerModels = JSON.parse(startObj.syscallAnalyzerModels)
      this.performanceAnalyzerModels = JSON.parse(startObj.performanceAnalyzerModels),
      this.syscallDetectorModels = JSON.parse(startObj.syscallDetectorModels),
      this.performanceDetectorModels = JSON.parse(startObj.performanceDetectorModels)

      console.log(this.osData, this.mwData, this.syscallAnalyzerModels)
    }
}
</script>
