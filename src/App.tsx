import {useState, useCallback} from 'react';
import {useDropzone} from 'react-dropzone';
import {
  Shield,
  Upload,
  Activity,
  FileText,
  AlertTriangle,
  Lock,
  Search,
  ChevronRight,
  Terminal,
  Globe,
  Database,
  Download,
  ExternalLink,
  Zap
} from 'lucide-react';
import {motion, AnimatePresence} from 'motion/react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area
} from 'recharts';
import {clsx, type ClassValue} from 'clsx';
import {twMerge} from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Types for Wireshark JSON export parsing
interface Packet {
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  raw: any;
}

export default function App() {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [timeSeriesData, setTimeSeriesData] = useState<any[]>([]);
  const [selectedTask, setSelectedTask] = useState('general');

  const tasks = [
    { id: 'general', name: 'General Triage', icon: Shield },
    { id: 'ioc', name: 'Extract IoCs', icon: Search },
    { id: 'c2', name: 'C2 Beaconing', icon: Globe },
    { id: 'payload', name: 'Dropped Payloads', icon: Download },
    { id: 'exfiltration', name: 'Data Exfiltration', icon: ExternalLink },
    { id: 'exploit', name: 'Exploit Kits', icon: Zap }
  ];

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const json = JSON.parse(reader.result as string);
        const normalized: Packet[] = json.map((p: any, index: number) => {
          const source = p._source?.layers;
          return {
            timestamp: source?.frame?.['frame.time'] || new Date().toISOString(),
            source: source?.ip?.['ip.src'] || source?.ipv6?.['ipv6.src'] || 'unknown',
            destination: source?.ip?.['ip.dst'] || source?.ipv6?.['ipv6.dst'] || 'unknown',
            protocol: source?.frame?.['frame.protocols']?.split(':').pop() || 'TCP',
            length: parseInt(source?.frame?.['frame.len']) || 0,
            info: `Packet ${index + 1}`,
            raw: p
          };
        });
        setPackets(normalized);
        
        const timeline = normalized.reduce((acc: any, curr) => {
          const time = curr.timestamp.split(':').slice(0, 2).join(':');
          acc[time] = (acc[time] || 0) + 1;
          return acc;
        }, {});
        
        setTimeSeriesData(Object.entries(timeline).map(([time, count]) => ({time, count})));
      } catch (e) {
        console.error("Failed to parse Wireshark JSON", e);
        alert("Please upload a valid Wireshark JSON export.");
      }
    };
    reader.readAsText(file);
  }, []);

  const {getRootProps, getInputProps, isDragActive} = useDropzone({
    onDrop,
    accept: {'application/json': ['.json']},
    multiple: false
  } as any);

  const analyzeTraffic = async () => {
    if (packets.length === 0) return;
    setIsAnalyzing(true);
    setAnalysis(null);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          task: selectedTask,
          packets: packets.slice(0, 50).map(p => ({
            src: p.source,
            dst: p.destination,
            proc: p.protocol,
            info: p.info
          }))
        })
      });
      const data = await response.json();
      setAnalysis(data.analysis);
    } catch (e) {
      console.error(e);
      setAnalysis("Analysis failed. Please check server connection.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans flex flex-col">
      {/* Navbar */}
      <header className="bg-white border-b border-slate-200 px-6 py-4 flex justify-between items-center sticky top-0 z-10 shadow-sm">
        <div className="flex items-center gap-2">
          <Activity className="w-6 h-6 text-indigo-600" />
          <h1 className="font-semibold text-lg tracking-tight">Malware Traffic Analyzer</h1>
        </div>
        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
            {tasks.map((task) => (
              <button
                key={task.id}
                onClick={() => setSelectedTask(task.id)}
                className={cn(
                  "flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
                  selectedTask === task.id ? "bg-white text-indigo-600 shadow-sm" : "text-slate-500 hover:text-slate-700"
                )}
              >
                <task.icon className="w-3.5 h-3.5" />
                {task.name}
              </button>
            ))}
          </div>
          {packets.length > 0 && (
            <button 
              onClick={analyzeTraffic}
              disabled={isAnalyzing}
              className="flex items-center gap-2 bg-indigo-600 text-white px-5 py-2 rounded-lg font-medium text-sm hover:bg-indigo-700 transition-colors disabled:opacity-50 shadow-sm"
            >
              {isAnalyzing ? <Activity className="w-4 h-4 animate-spin" /> : <Terminal className="w-4 h-4" />}
              Run {tasks.find(t => t.id === selectedTask)?.name}
            </button>
          )}
        </div>
      </header>

      <main className="flex-1 flex flex-col max-w-[1600px] mx-auto w-full p-6 gap-6">
        {packets.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <div 
              {...getRootProps()} 
              className={cn(
                "w-full max-w-2xl p-16 border-2 border-dashed rounded-2xl flex flex-col items-center justify-center gap-4 transition-all bg-white",
                isDragActive ? "border-indigo-500 bg-indigo-50" : "border-slate-300 hover:border-slate-400"
              )}
            >
              <input {...getInputProps()} />
              <div className="w-16 h-16 bg-indigo-100 text-indigo-600 rounded-full flex items-center justify-center mb-2">
                <Upload className="w-8 h-8" />
              </div>
              <div className="text-center">
                <h2 className="text-2xl font-semibold text-slate-800 mb-2">Analyze Network Traffic</h2>
                <p className="text-slate-500 max-w-sm">Drag and drop your Wireshark JSON export here to begin the malware detection process.</p>
                <div className="mt-6 inline-flex items-center gap-2 text-xs font-medium text-slate-400 bg-slate-100 px-3 py-1 rounded-full">
                  <FileText className="w-3 h-3" />
                  JSON FORMAT REQUIRED
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 overflow-hidden">
            {/* Left Panel: Packet List */}
            <div className="lg:col-span-8 flex flex-col gap-6">
              {/* Stats Grid */}
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Total Packets</p>
                  <p className="text-2xl font-bold text-slate-800">{packets.length.toLocaleString()}</p>
                </div>
                <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Unique Endpoints</p>
                  <p className="text-2xl font-bold text-slate-800">{new Set(packets.map(p => p.source)).size}</p>
                </div>
                <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Risk Score</p>
                  <p className={cn(
                    "text-2xl font-bold",
                    analysis ? "text-rose-600" : "text-slate-400"
                  )}>{analysis ? "Critical" : "Scanning..."}</p>
                </div>
              </div>

              {/* Table Container */}
              <div className="flex-1 bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden flex flex-col">
                <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
                  <h3 className="font-semibold text-slate-800">Traffic Inspection</h3>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input 
                      type="text" 
                      placeholder="Search traffic..." 
                      className="pl-9 pr-4 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                    />
                  </div>
                </div>
                <div className="flex-1 overflow-auto">
                  <table className="w-full text-left">
                    <thead className="bg-slate-50 sticky top-0 text-[11px] font-bold text-slate-500 uppercase tracking-wider border-b border-slate-200">
                      <tr>
                        <th className="px-6 py-3">No.</th>
                        <th className="px-6 py-3">Source IP</th>
                        <th className="px-6 py-3">Destination IP</th>
                        <th className="px-6 py-3">Protocol</th>
                        <th className="px-6 py-3">Length</th>
                        <th className="px-6 py-3">Time</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 text-sm">
                      {packets.map((p, i) => (
                        <tr 
                          key={i} 
                          onClick={() => setSelectedPacket(p)}
                          className={cn(
                            "cursor-pointer transition-colors",
                            selectedPacket === p ? "bg-indigo-50" : "hover:bg-slate-50"
                          )}
                        >
                          <td className="px-6 py-3 text-slate-400 font-mono text-xs">{i + 1}</td>
                          <td className="px-6 py-3 font-medium">{p.source}</td>
                          <td className="px-6 py-3 font-medium">{p.destination}</td>
                          <td className="px-6 py-3">
                            <span className={cn(
                              "px-2 py-0.5 rounded-full text-[10px] font-bold uppercase",
                              p.protocol === 'HTTP' ? "bg-amber-100 text-amber-700" :
                              p.protocol === 'TLS' ? "bg-emerald-100 text-emerald-700" :
                              p.protocol === 'DNS' ? "bg-sky-100 text-sky-700" :
                              "bg-slate-100 text-slate-600"
                            )}>
                              {p.protocol}
                            </span>
                          </td>
                          <td className="px-6 py-3 text-slate-500">{p.length} B</td>
                          <td className="px-6 py-3 text-slate-400 font-mono text-[11px]">{p.timestamp.split(' ').pop()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Right Panel: Side Intelligence */}
            <div className="lg:col-span-4 flex flex-col gap-6">
              {/* Traffic Visualizer */}
              <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-6">
                <h3 className="text-sm font-semibold text-slate-800 mb-6 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-indigo-500" />
                  Traffic Volume
                </h3>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timeSeriesData}>
                      <defs>
                        <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#6366f1" stopOpacity={0.1}/>
                          <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                      <XAxis dataKey="time" hide />
                      <YAxis hide />
                      <Tooltip 
                        contentStyle={{borderRadius: '8px', border: 'none', boxShadow: '0 4px 12px rgba(0,0,0,0.1)'}}
                      />
                      <Area type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="url(#colorCount)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Actionable Report Card */}
              <div className="flex-1 bg-slate-900 text-white rounded-2xl shadow-xl overflow-hidden flex flex-col">
                <div className="p-6 border-b border-white/10 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Shield className="w-5 h-5 text-indigo-400" />
                    <h3 className="font-semibold text-sm">Security Assessment</h3>
                  </div>
                  {isAnalyzing && <Activity className="w-4 h-4 animate-spin text-indigo-400" />}
                </div>

                <div className="flex-1 p-6 overflow-auto">
                  <AnimatePresence mode="wait">
                    {isAnalyzing ? (
                      <motion.div 
                        initial={{opacity: 0}}
                        animate={{opacity: 1}}
                        exit={{opacity: 0}}
                        className="space-y-4"
                      >
                        <div className="h-3 bg-white/10 rounded w-full animate-pulse"></div>
                        <div className="h-3 bg-white/10 rounded w-4/5 animate-pulse"></div>
                        <div className="h-3 bg-white/10 rounded w-3/4 animate-pulse"></div>
                        <div className="pt-8 flex flex-col items-center justify-center text-center">
                          <Activity className="w-8 h-8 text-indigo-500 mb-4 animate-spin" />
                          <p className="text-sm font-medium text-white/60">Triage running via AI Insight...</p>
                        </div>
                      </motion.div>
                    ) : analysis ? (
                      <motion.div 
                        initial={{opacity: 0, scale: 0.95}}
                        animate={{opacity: 1, scale: 1}}
                        className="prose prose-invert prose-sm"
                      >
                        <div className="bg-indigo-500/10 border border-indigo-500/20 p-4 rounded-xl mb-6">
                            <p className="text-[10px] uppercase font-bold tracking-widest text-indigo-400 mb-1">Packet Context</p>
                            <p className="text-xs text-white/80">{selectedPacket ? `Inspecting: ${selectedPacket.source} -> ${selectedPacket.destination}` : 'Top-level traffic analysis complete.'}</p>
                        </div>
                        <div className="whitespace-pre-wrap text-sm leading-relaxed text-indigo-50 font-mono opacity-90">
                          {analysis}
                        </div>
                      </motion.div>
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center text-center opacity-40">
                        <AlertTriangle className="w-10 h-10 mb-4" />
                        <p className="text-sm">Run AI analysis to check for C2 beacons and malicious exfiltration.</p>
                      </div>
                    )}
                  </AnimatePresence>
                </div>
                
                <div className="p-6 bg-white/5 border-t border-white/10">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-indigo-500/20 flex items-center justify-center">
                      <Lock className="w-4 h-4 text-indigo-400" />
                    </div>
                    <div>
                      <p className="text-[10px] font-bold text-white/40 uppercase tracking-widest">Environment</p>
                      <p className="text-xs text-white/70">Secure Sandbox Analysis</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="py-4 px-6 border-t border-slate-200 bg-white text-slate-400 text-xs flex justify-between">
        <p>&copy; {new Date().getFullYear()} Network Analysis Dashboard</p>
        <div className="flex gap-4">
          <span className="flex items-center gap-1"><Globe className="w-3 h-3" /> System Live</span>
          <span className="flex items-center gap-1"><Database className="w-3 h-3" /> Ready</span>
        </div>
      </footer>
    </div>
  );
}
