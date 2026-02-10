
import numpy as np
import pandas as pd

class StatisticalAnomalyDetector:
    def __init__(self):
        self.cpu_mean = 0.0
        self.cpu_std = 0.0
        self.mem_mean = 0.0
        self.mem_std = 0.0
        self.trained = False

    def train(self, processes: list):
        """
        Learns the baseline from the current list of processes.
        """
        if not processes:
            return

        df = pd.DataFrame(processes)
        
        # CPU Stats
        if 'cpu_percent' in df.columns:
            self.cpu_mean = df['cpu_percent'].mean()
            self.cpu_std = df['cpu_percent'].std()
            if self.cpu_std == 0: self.cpu_std = 1.0 # Avoid div by zero

        # Memory Stats
        if 'memory_percent' in df.columns:
            self.mem_mean = df['memory_percent'].mean()
            self.mem_std = df['memory_percent'].std()
            if self.mem_std == 0: self.mem_std = 1.0

        self.trained = True

    def detect(self, processes: list, threshold=3.0):
        """
        Returns processes that deviate more than 'threshold' std devs from the mean.
        """
        if not self.trained:
            self.train(processes)
        
        anomalies = []
        for p in processes:
            reasons = []
            score = 0.0
            
            # CPU Z-Score
            cpu = p.get('cpu_percent', 0)
            z_cpu = (cpu - self.cpu_mean) / self.cpu_std
            if z_cpu > threshold:
                reasons.append(f"High CPU (Z={z_cpu:.1f})")
                score += z_cpu

            # Mem Z-Score
            mem = p.get('memory_percent', 0)
            z_mem = (mem - self.mem_mean) / self.mem_std
            if z_mem > threshold:
                reasons.append(f"High Memory (Z={z_mem:.1f})")
                score += z_mem
            
            if reasons:
                p_copy = p.copy()
                p_copy['anomaly_score'] = score
                p_copy['anomaly_reasons'] = ", ".join(reasons)
                anomalies.append(p_copy)
        
        # Sort by score
        anomalies.sort(key=lambda x: x['anomaly_score'], reverse=True)
        return anomalies
