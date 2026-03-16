"""
network_pattern_analyzer.py

NETWORK PATTERN ANALYZER
- Load export files from Network Stability Monitor
- Analyze patterns in network incidents
- Detect time correlations and frequency patterns
- Generate analysis reports

Dependencies:
  pip install customtkinter
"""

import os
import json
import glob
from datetime import datetime
from typing import Dict, List, Any, Tuple
from collections import defaultdict, Counter

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk

TOOL_NAME = "Network Pattern Analyzer"

class NetworkPatternAnalyzer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Pattern Analyzer")
        self.root.geometry("1000x700")
        
        self.export_data: List[Dict] = []
        self.analysis_results: Dict[str, Any] = {}
        
        self._build_ui()
        
    def _build_ui(self):
        """Build the user interface"""
        # Main container
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(main_frame, text="🔍 Network Pattern Analyzer", 
                     font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        
        # Control panel
        control_frame = ctk.CTkFrame(main_frame)
        control_frame.pack(fill="x", pady=10)
        
        # Buttons
        button_frame = ctk.CTkFrame(control_frame)
        button_frame.pack(pady=10)
        
        ctk.CTkButton(button_frame, text="📁 Load Exports", 
                     command=self.load_exports, width=150, height=40).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="🔬 Analyze", 
                     command=self.analyze_patterns, width=150, height=40).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="💾 Export Analysis", 
                     command=self.export_analysis, width=150, height=40).pack(side="left", padx=10)
        
        # Status label
        self.status_label = ctk.CTkLabel(control_frame, text="Ready to load export files...", 
                                        font=ctk.CTkFont(size=12))
        self.status_label.pack(pady=5)
        
        # Results panel
        results_frame = ctk.CTkFrame(main_frame)
        results_frame.pack(fill="both", expand=True, pady=10)
        
        ctk.CTkLabel(results_frame, text="Analysis Results", 
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # Results text area
        self.results_text = ctk.CTkTextbox(results_frame, wrap="word")
        self.results_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.results_text.insert("1.0", "Load export files and click 'Analyze' to see patterns...")
        self.results_text.configure(state="disabled")
        
    def load_exports(self):
        """Load all export files from the exports folder"""
        try:
            # Look for export files
            export_pattern = os.path.join("exports", "network_export_*.json")
            export_files = glob.glob(export_pattern)
            
            if not export_files:
                messagebox.showwarning("No Files", "No export files found in 'exports' folder.")
                self.status_label.configure(text="No export files found")
                return
                
            self.export_data.clear()
            incidents_count = 0
            events_count = 0
            
            # Load each export file
            for file_path in sorted(export_files):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        self.export_data.append(data)
                        incidents_count += len(data.get('incidents', []))
                        events_count += len(data.get('events', []))
                except Exception as e:
                    print(f"Error loading {file_path}: {e}")
                    
            self.status_label.configure(
                text=f"Loaded {len(export_files)} export files: {incidents_count} incidents, {events_count} events"
            )
            self.results_text.configure(state="normal")
            self.results_text.delete("1.0", tk.END)
            self.results_text.insert("1.0", f"✅ Successfully loaded {len(export_files)} export files:\n\n")
            self.results_text.insert(tk.END, f"📊 Total incidents: {incidents_count}\n")
            self.results_text.insert(tk.END, f"📋 Total events: {events_count}\n\n")
            
            for file_path in sorted(export_files):
                filename = os.path.basename(file_path)
                self.results_text.insert(tk.END, f"📄 {filename}\n")
                
            self.results_text.insert(tk.END, f"\nClick 'Analyze' to detect patterns...")
            self.results_text.configure(state="disabled")
            
        except Exception as e:
            messagebox.showerror("Load Error", f"Error loading export files:\n{e}")
            self.status_label.configure(text="Error loading files")
            
    def analyze_patterns(self):
        """Analyze patterns in the loaded export data"""
        if not self.export_data:
            messagebox.showwarning("No Data", "Please load export files first.")
            return
            
        try:
            # Merge all incidents from all files
            all_incidents = []
            all_events = []
            
            for export in self.export_data:
                all_incidents.extend(export.get('incidents', []))
                all_events.extend(export.get('events', []))
                
            if not all_incidents:
                messagebox.showinfo("No Incidents", "No incidents found in the export data.")
                return
                
            # Perform analysis
            self.analysis_results = {
                'summary': self._analyze_summary(all_incidents, all_events),
                'time_distribution': self._analyze_time_distribution(all_incidents),
                'category_frequency': self._analyze_category_frequency(all_incidents),
                'average_duration': self._analyze_average_duration(all_incidents),
                'repeating_time_windows': self._analyze_repeating_time_windows(all_incidents),
                'sequential_correlations': self._analyze_sequential_correlations(all_incidents)
            }
            
            # Display results
            self._display_results()
            self.status_label.configure(text="Analysis complete!")
            
        except Exception as e:
            messagebox.showerror("Analysis Error", f"Error during analysis:\n{e}")
            self.status_label.configure(text="Analysis failed")
            
    def _analyze_summary(self, incidents: List[Dict], events: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics"""
        return {
            'total_incidents': len(incidents),
            'total_events': len(events),
            'date_range': self._get_date_range(incidents),
            'unique_categories': len(set(inc.get('category', 'UNKNOWN') for inc in incidents))
        }
        
    def _analyze_time_distribution(self, incidents: List[Dict]) -> Dict[str, int]:
        """Analyze incidents per hour"""
        incidents_per_hour = {f"{i:02d}": 0 for i in range(24)}
        
        for inc in incidents:
            start_time = self._parse_timestamp(inc.get('start_time', ''))
            if start_time:
                hour_key = f"{start_time.hour:02d}"
                incidents_per_hour[hour_key] += 1
                
        return incidents_per_hour
        
    def _analyze_category_frequency(self, incidents: List[Dict]) -> Dict[str, int]:
        """Count incidents per category"""
        category_count = Counter()
        for inc in incidents:
            category = inc.get('category', 'UNKNOWN')
            category_count[category] += 1
        return dict(category_count)
        
    def _analyze_average_duration(self, incidents: List[Dict]) -> Dict[str, float]:
        """Calculate average duration per category"""
        durations_by_category = defaultdict(list)
        
        for inc in incidents:
            if inc.get('end_time') and inc.get('start_time'):
                duration = self._calculate_duration_seconds(inc['start_time'], inc['end_time'])
                if duration is not None:
                    category = inc.get('category', 'UNKNOWN')
                    durations_by_category[category].append(duration)
                    
        # Calculate averages
        avg_durations = {}
        for category, durations in durations_by_category.items():
            if durations:
                avg_durations[category] = sum(durations) / len(durations)
                
        return avg_durations
        
    def _analyze_repeating_time_windows(self, incidents: List[Dict]) -> List[Dict]:
        """Detect hours with high incident frequency"""
        incidents_by_hour = defaultdict(int)
        
        for inc in incidents:
            start_time = self._parse_timestamp(inc.get('start_time', ''))
            if start_time:
                incidents_by_hour[start_time.hour] += 1
                
        # Find high-frequency hours (above average)
        if incidents_by_hour:
            avg_incidents = sum(incidents_by_hour.values()) / len(incidents_by_hour)
            high_frequency_hours = [
                {'hour': hour, 'incidents': count, 'above_average': count > avg_incidents}
                for hour, count in incidents_by_hour.items()
                if count > avg_incidents
            ]
            return sorted(high_frequency_hours, key=lambda x: x['incidents'], reverse=True)
        return []
        
    def _analyze_sequential_correlations(self, incidents: List[Dict]) -> List[Dict]:
        """Detect patterns where one category follows another within 10 minutes"""
        correlations = defaultdict(int)
        total_pairs = 0
        
        # Sort incidents by start time
        sorted_incidents = sorted(incidents, key=lambda x: x.get('start_time', ''))
        
        for i in range(len(sorted_incidents) - 1):
            current = sorted_incidents[i]
            next_inc = sorted_incidents[i + 1]
            
            current_time = self._parse_timestamp(current.get('start_time', ''))
            next_time = self._parse_timestamp(next_inc.get('start_time', ''))
            
            if current_time and next_time:
                time_diff = (next_time - current_time).total_seconds() / 60  # minutes
                
                if time_diff <= 10:  # Within 10 minutes
                    current_cat = current.get('category', 'UNKNOWN')
                    next_cat = next_inc.get('category', 'UNKNOWN')
                    correlations[f"{current_cat} → {next_cat}"] += 1
                    total_pairs += 1
                    
        # Calculate percentages
        correlation_patterns = []
        for pattern, count in correlations.items():
            if total_pairs > 0:
                percentage = (count / total_pairs) * 100
                correlation_patterns.append({
                    'pattern': pattern,
                    'occurrences': count,
                    'percentage': percentage
                })
                
        return sorted(correlation_patterns, key=lambda x: x['percentage'], reverse=True)
        
    def _display_results(self):
        """Display analysis results in the text area"""
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", tk.END)
        
        results = self.analysis_results
        
        # Summary
        summary = results['summary']
        self.results_text.insert(tk.END, "📊 SUMMARY\n", "heading")
        self.results_text.insert(tk.END, "=" * 50 + "\n\n")
        self.results_text.insert(tk.END, f"Total Incidents: {summary['total_incidents']}\n")
        self.results_text.insert(tk.END, f"Total Events: {summary['total_events']}\n")
        self.results_text.insert(tk.END, f"Date Range: {summary['date_range']}\n")
        self.results_text.insert(tk.END, f"Unique Categories: {summary['unique_categories']}\n\n")
        
        # Time Distribution
        self.results_text.insert(tk.END, "⏰ INCIDENTS PER HOUR\n", "heading")
        self.results_text.insert(tk.END, "=" * 50 + "\n")
        time_dist = results['time_distribution']
        for hour in sorted(time_dist.keys()):
            count = time_dist[hour]
            bar = "█" * min(count, 20)  # Simple bar chart
            self.results_text.insert(tk.END, f"{hour}:00 - {count:2d} {bar}\n")
        self.results_text.insert(tk.END, "\n")
        
        # Category Frequency
        self.results_text.insert(tk.END, "📈 CATEGORY FREQUENCY\n", "heading")
        self.results_text.insert(tk.END, "=" * 50 + "\n")
        cat_freq = results['category_frequency']
        for category, count in sorted(cat_freq.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / summary['total_incidents']) * 100
            self.results_text.insert(tk.END, f"{category}: {count} ({percentage:.1f}%)\n")
        self.results_text.insert(tk.END, "\n")
        
        # Average Duration
        self.results_text.insert(tk.END, "⏱️ AVERAGE DURATION BY CATEGORY\n", "heading")
        self.results_text.insert(tk.END, "=" * 50 + "\n")
        avg_dur = results['average_duration']
        for category, duration in sorted(avg_dur.items(), key=lambda x: x[1], reverse=True):
            minutes = duration / 60
            self.results_text.insert(tk.END, f"{category}: {minutes:.1f} minutes\n")
        self.results_text.insert(tk.END, "\n")
        
        # High Frequency Time Windows
        self.results_text.insert(tk.END, "🔥 HIGH FREQUENCY TIME WINDOWS\n", "heading")
        self.results_text.insert(tk.END, "=" * 50 + "\n")
        high_freq = results['repeating_time_windows']
        if high_freq:
            for window in high_freq[:5]:  # Top 5
                hour = window['hour']
                incidents = window['incidents']
                self.results_text.insert(tk.END, f"{hour:02d}:00-{hour:02d}:59 - {incidents} incidents (above average)\n")
        else:
            self.results_text.insert(tk.END, "No high-frequency time windows detected\n")
        self.results_text.insert(tk.END, "\n")
        
        # Sequential Correlations
        self.results_text.insert(tk.END, "🔗 SEQUENTIAL CORRELATIONS (within 10 minutes)\n", "heading")
        self.results_text.insert(tk.END, "=" * 50 + "\n")
        correlations = results['sequential_correlations']
        if correlations:
            for corr in correlations[:10]:  # Top 10
                pattern = corr['pattern']
                percentage = corr['percentage']
                occurrences = corr['occurrences']
                self.results_text.insert(tk.END, f"{pattern}: {percentage:.1f}% ({occurrences} cases)\n")
        else:
            self.results_text.insert(tk.END, "No sequential correlations detected\n")
            
        self.results_text.configure(state="disabled")
        
    def export_analysis(self):
        """Export analysis results to JSON file"""
        if not self.analysis_results:
            messagebox.showwarning("No Analysis", "Please run analysis first.")
            return
            
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
                title="Save analysis results",
                initialfile="network_pattern_analysis.json"
            )
            
            if not file_path:
                return
                
            # Prepare export data
            export_data = {
                'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'export_files_analyzed': len(self.export_data),
                'summary': self.analysis_results['summary'],
                'patterns': {
                    'time_distribution': self.analysis_results['time_distribution'],
                    'category_frequency': self.analysis_results['category_frequency'],
                    'average_duration_by_category': self.analysis_results['average_duration'],
                    'high_frequency_time_windows': self.analysis_results['repeating_time_windows'],
                    'sequential_correlations': self.analysis_results['sequential_correlations']
                }
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
                
            messagebox.showinfo("Export Complete", f"Analysis results saved to:\n{file_path}")
            self.status_label.configure(text="Analysis exported successfully")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting analysis:\n{e}")
            
    # Helper methods
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime object"""
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None
            
    def _calculate_duration_seconds(self, start_time: str, end_time: str) -> float:
        """Calculate duration in seconds between two timestamps"""
        start = self._parse_timestamp(start_time)
        end = self._parse_timestamp(end_time)
        if start and end:
            return (end - start).total_seconds()
        return None
        
    def _get_date_range(self, incidents: List[Dict]) -> str:
        """Get date range from incidents"""
        if not incidents:
            return "No data"
            
        timestamps = []
        for inc in incidents:
            ts = self._parse_timestamp(inc.get('start_time', ''))
            if ts:
                timestamps.append(ts)
                
        if not timestamps:
            return "No valid timestamps"
            
        min_date = min(timestamps).strftime("%Y-%m-%d")
        max_date = max(timestamps).strftime("%Y-%m-%d")
        
        if min_date == max_date:
            return min_date
        else:
            return f"{min_date} to {max_date}"
            
    def run(self):
        """Run the application"""
        self.root.mainloop()

def run_tool():
    """Tool entry point"""
    try:
        app = NetworkPatternAnalyzer()
        app.run()
    except Exception as e:
        messagebox.showerror("Network Pattern Analyzer", f"Startup error:\n{e}")

if __name__ == "__main__":
    run_tool()
