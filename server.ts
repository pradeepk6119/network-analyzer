import express from 'express';
import {createServer as createViteServer} from 'vite';
import {GoogleGenAI, Type} from '@google/genai';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({limit: '50mb'}));

  // Gemini Analysis Endpoint
  app.post('/api/analyze', async (req, res) => {
    try {
      const { packets, task } = req.body;
      
      const taskPrompts: Record<string, string> = {
        ioc: "Extract Indicators of Compromise (IoCs). Identify malicious IPs, domain names, URLs, and file paths. Format as a clean list of IoCs.",
        c2: "Identify Command and Control (C2) Traffic. Look for beaconing patterns, unusual protocol usage, check-in frequencies, and potential heartbeat signals.",
        payload: "Look for evidence of Dropped Payloads or secondary downloads. Identify HTTP/HTTPS transfers of executable content or suspicious script downloads.",
        exfiltration: "Detect potential Data Exfiltration. Look for large outbound transfers, unusual data ratios, or sneaky techniques like DNS tunneling or ICMP exfiltration.",
        exploit: "Analyze for Exploit Kit activity. Trace redirection chains, look for landing pages, and identify patterns consistent with known vulnerability exploitation.",
        general: "Perform a general malware traffic triage. Identify the most suspicious activities and provide a risk assessment."
      };

      const focusPrompt = taskPrompts[task] || taskPrompts.general;
      
      const prompt = `Task: ${focusPrompt}
      
      Analyze the following network packets (first 50 in capture):
      ${JSON.stringify(packets)}
      
      Provide your response in a clear, professional security report format. Include:
      - Risk Level (Low, Medium, High, Critical)
      - Detailed Summary
      - Specific Evidence (Packets/IPs/Ports)
      - Mitigation Steps`;

      const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        config: {
          systemInstruction: "You are an expert SOC Analyst and Malware Traffic Researcher. You specialize in Wireshark analysis and threat hunting. Provide concise, expert-level feedback.",
        }
      });

      res.json({ analysis: response.text });
    } catch (error: any) {
      console.error('Gemini API Error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {middlewareMode: true},
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
