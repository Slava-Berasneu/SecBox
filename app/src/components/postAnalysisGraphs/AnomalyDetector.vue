<template>
  <div>
    <div class="table-container">
      <h2>Anomaly Detector</h2>
      <table class="custom-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Syscall Prediction</th>
            <th>Performance Prediction</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(entry, index) in mergedData" :key="index">
            <td>{{ entry.timestamp }}</td>
            <td :class="getSyscallPredictionClass(entry.syscallPrediction)">{{ entry.syscallPrediction }}</td>
            <td :class="getPerformancePredictionClass(entry.performancePrediction)">{{ entry.performancePrediction }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
import { io } from 'socket.io-client';



export default {
  data() {
    return {
      syscallData: [],
      performanceData: [],
      mergedData: []
    };
  },
  created() {
    this.socket = io("ws://"+process.env.VUE_APP_ROOT+"/live");

    this.socket.on('anomaly_syscall_data', data => {
      let parsedData = JSON.parse(data)
      if(!this.syscallData.includes(parsedData)){
        this.syscallData.push(parsedData)
        this.addSyscallEntry(parsedData);
      }
    });

    this.socket.on('anomaly_performance_data', data => {
      let parsedData = JSON.parse(data)
      if(!this.performanceData.includes(parsedData)){
        this.performanceData.push(parsedData)
        this.addPerformanceEntry(parsedData);
      }
    });

  },
  methods: {
    addPerformanceEntry(item){
      const existingEntry = this.mergedData.find(entry => entry.timestamp === item[0]);
      if (existingEntry){
        existingEntry.performancePrediction = item[1] === "1" ? 'inlier' : 'outlier';
      }
      else {
        this.mergedData.push({
          timestamp: item[0],
          syscallPrediction: 'Not Available',
          performancePrediction: item[1] === "1" ? 'inlier' : 'outlier',
        })
      }
    },

    addSyscallEntry(item){
      const existingEntry = this.mergedData.find(entry => entry.timestamp === item[0]);
      if (existingEntry){
        existingEntry.syscallPrediction = item[1] === "1" ? 'inlier' : 'outlier';
      }
      else {
        this.mergedData.push({
          timestamp: item[0],
          syscallPrediction: item[1] === "1" ? 'inlier' : 'outlier',
          performancePrediction: 'Not Available',
        })
      }
    },



    getSyscallPredictionClass(prediction) {
      return {
        'infected-cell': prediction === 'infected',
        'healthy-cell': prediction === 'healthy'
      };
    },
    getPerformancePredictionClass(prediction) {
      return {
        'infected-cell': prediction === 'infected',
        'healthy-cell': prediction === 'healthy'
      };
    }
  }
};
</script>

<style>
.table-container {
  height: 300px;
  overflow-y: scroll;
  background-color: black;
  border: 1px solid #ccc;
  padding: 10px;
}

.custom-table {
  width: 100%;
  border-collapse: collapse;
}

.custom-table th,
.custom-table td {
  border: 1px solid white;
  padding: 8px;
  color: white;
}

.custom-table th {
  background-color: #333;
}

.custom-table tbody tr:nth-child(even) {
  background-color: #444;
}

.custom-table tbody tr:hover {
  background-color: #555;
}

.infected-cell {
  color: red;
}

.healthy-cell {
  color: green;
}
</style>