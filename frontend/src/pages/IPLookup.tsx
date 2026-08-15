import { useState } from 'react';
import { Search, Shield, Loader2, Brain, Globe, AlertTriangle, ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';

type DbThreat = {
  id: string;
  ip: string;
  port: number;
  type: string;
  severity: string;
  created_at: string;
};

type DbIPProfile = {
  ip: string;
  score: number;
  total_attacks: number;
  country: string;
  attack_types: Record<string, number>;
};

interface AbuseIPDBData {
  available: boolean;
  reason?: string;
  ip?: string;
  isPublic?: boolean;
  abuseConfidenceScore?: number;
  countryCode?: string;
  countryName?: string;
  isp?: string;
  domain?: string;
  usageType?: string;
  totalReports?: number;
  numDistinctUsers?: number;
  lastReportedAt?: string | null;
  isTor?: boolean;
  isWhitelisted?: boolean;
  recentReports?: {
    reportedAt: string;
    comment: string;
    categories: number[];
    reporterId: number;
    reporterCountryCode: string;
  }[];
}

const CATEGORY_NAMES: Record<number, string> = {
  1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
  5: "FTP Brute-Force", 7: "Ping of Death", 8: "Phishing", 9: "Fraud VoIP",
  10: "Email Spam", 11: "Email Spoofing", 14: "Port Scan", 15: "Hacking",
  16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot",
  20: "Exploited Host", 21: "Web Spam", 22: "SSH", 23: "IoT Targeted",
};

export default function IPLookup() {
  const [query, setQuery] = useState('');
  const [profile, setProfile] = useState<DbIPProfile | null>(null);
  const [threats, setThreats] = useState<DbThreat[]>([]);
  const [abuseData, setAbuseData] = useState<AbuseIPDBData | null>(null);
  const [loading, setLoading] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [analyzingAI, setAnalyzingAI] = useState(false);
  const { toast } = useToast();

  const handleSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setAiAnalysis(null);
    setAbuseData(null);

    try {
      const res = await fetch(`/api/ip-lookup/${encodeURIComponent(query.trim())}`);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || 'Failed to fetch IP data');
      }
      const data = await res.json();

      setProfile(data.profile);
      setThreats(data.threats || []);
      setAbuseData(data.abuseData);

      if (data.abuseData?.available && !data.profile && !data.abuseData.totalReports) {
        toast({ title: 'Clean IP', description: `${query.trim()} has no abuse reports` });
      }
    } catch (e) {
      console.error('Search error:', e);
      toast({
        title: 'Lookup Failed',
        description: e instanceof Error ? e.message : 'Could not look up this IP',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const runAIAnalysis = async () => {
    setAnalyzingAI(true);
    try {
      const res = await fetch('/api/analyze-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: query.trim() }),
      });
      if (!res.ok) throw new Error('Failed to analyze');
      const data = await res.json();
      setAiAnalysis(data.analysis);
    } catch (e) {
      console.error('AI analysis error:', e);
      toast({ title: 'AI Analysis Failed', description: 'Could not complete threat analysis', variant: 'destructive' });
    } finally {
      setAnalyzingAI(false);
    }
  };

  const score = (abuseData?.available ? abuseData.abuseConfidenceScore : undefined) ?? profile?.score ?? 0;
  const scoreColor = score >= 70 ? 'text-destructive' : score >= 40 ? 'text-warning' : 'text-success';
  const scoreLabel = score >= 70 ? 'CRITICAL' : score >= 40 ? 'SUSPICIOUS' : 'LOW RISK';
  const hasData = Boolean(profile || abuseData?.available);

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold font-display text-foreground">IP Lookup</h1>
        <p className="text-sm font-mono text-muted-foreground">Real-time threat intelligence powered by AbuseIPDB</p>
      </div>

      {abuseData && !abuseData.available && (
        <div className="max-w-2xl rounded-md border border-warning/30 bg-warning/10 p-3 text-xs font-mono text-warning">
          {abuseData.reason || 'AbuseIPDB intelligence is currently unavailable.'} Local history is shown when available.
        </div>
      )}

      {/* Search bar */}
      <div className="flex gap-3">
        <div className="relative flex-1 max-w-lg">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder="Enter any IP address (e.g. 185.220.101.1)"
            className="w-full pl-10 pr-4 py-3 bg-card border border-border rounded-lg text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
          />
        </div>
        <button
          onClick={handleSearch}
          disabled={loading}
          className="px-6 py-3 bg-primary text-primary-foreground rounded-lg font-mono text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
        >
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'SCAN'}
        </button>
      </div>

      {hasData && (
        <div className="space-y-6">
          {/* Overview cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Score card */}
            <div className="bg-card/80 border border-border rounded-lg p-6 flex flex-col items-center justify-center">
              <div className={cn('text-5xl font-bold font-mono', scoreColor)}>{score}</div>
              <div className={cn('text-xs font-mono mt-1 uppercase tracking-wider', scoreColor)}>{scoreLabel}</div>
              <p className="text-xs font-mono text-muted-foreground mt-3">ABUSE CONFIDENCE</p>
              {abuseData?.available && abuseData.ip && (
                <a
                  href={`https://www.abuseipdb.com/check/${abuseData.ip}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] font-mono text-primary flex items-center gap-1 mt-2 hover:underline"
                >
                  View on AbuseIPDB <ExternalLink className="h-2.5 w-2.5" />
                </a>
              )}
            </div>

            {/* AbuseIPDB Details */}
            <div className="bg-card/80 border border-border rounded-lg p-6 space-y-3">
              <h3 className="text-xs font-mono text-primary uppercase tracking-wider flex items-center gap-2">
                <Globe className="h-3 w-3" /> Real Intelligence
              </h3>
              <div className="space-y-2 font-mono text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">IP</span>
                  <span className="text-foreground">{abuseData?.ip || profile?.ip}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Country</span>
                  <span className="text-foreground">{abuseData?.countryName || abuseData?.countryCode || profile?.country || "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">ISP</span>
                  <span className="text-foreground text-xs truncate max-w-[160px]">{abuseData?.isp || "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Domain</span>
                  <span className="text-foreground">{abuseData?.domain || "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Usage</span>
                  <span className="text-foreground text-xs">{abuseData?.usageType || "—"}</span>
                </div>
              </div>
            </div>

            {/* Stats card */}
            <div className="bg-card/80 border border-border rounded-lg p-6 space-y-3">
              <h3 className="text-xs font-mono text-primary uppercase tracking-wider flex items-center gap-2">
                <AlertTriangle className="h-3 w-3" /> Abuse Stats
              </h3>
              <div className="space-y-2 font-mono text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Reports</span>
                  <span className="text-destructive font-bold">{abuseData?.totalReports ?? profile?.total_attacks ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Distinct Reporters</span>
                  <span className="text-foreground">{abuseData?.numDistinctUsers ?? "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Tor Exit Node</span>
                  <span className={abuseData?.isTor ? "text-destructive" : "text-success"}>{abuseData?.isTor ? "YES" : "NO"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Last Report</span>
                  <span className="text-foreground text-xs">{abuseData?.lastReportedAt ? new Date(abuseData.lastReportedAt).toLocaleDateString() : "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Whitelisted</span>
                  <span className={abuseData?.isWhitelisted ? "text-success" : "text-muted-foreground"}>{abuseData?.isWhitelisted ? "YES" : "NO"}</span>
                </div>
              </div>
            </div>
          </div>

          {/* AI Analysis */}
          <div className="bg-card/80 border border-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-mono text-primary uppercase tracking-wider flex items-center gap-2">
                <Brain className="h-4 w-4" />
                AI Threat Analysis
              </h3>
              <button
                onClick={runAIAnalysis}
                disabled={analyzingAI}
                className="px-4 py-2 bg-accent/20 text-accent border border-accent/30 rounded-md font-mono text-xs hover:bg-accent/30 transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {analyzingAI ? <Loader2 className="h-3 w-3 animate-spin" /> : <Brain className="h-3 w-3" />}
                {analyzingAI ? 'ANALYZING...' : 'RUN ANALYSIS'}
              </button>
            </div>
            {aiAnalysis ? (
              <div className="prose prose-sm prose-invert max-w-none font-mono text-xs text-foreground/90 whitespace-pre-wrap leading-relaxed">
                {aiAnalysis}
              </div>
            ) : (
              <p className="text-xs font-mono text-muted-foreground">
                Click "Run Analysis" for AI-powered threat assessment using real AbuseIPDB data
              </p>
            )}
          </div>

          {/* Recent community reports from AbuseIPDB */}
          {abuseData?.available && abuseData.recentReports && abuseData.recentReports.length > 0 && (
            <div className="bg-card/80 border border-border rounded-lg overflow-hidden">
              <div className="p-4 border-b border-border">
                <h3 className="text-sm font-mono text-primary uppercase tracking-wider">
                  Community Reports ({abuseData.totalReports ?? 0} total)
                </h3>
              </div>
              <div className="overflow-auto max-h-[400px]">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="border-b border-border text-muted-foreground">
                      <th className="text-left p-3">DATE</th>
                      <th className="text-left p-3">CATEGORIES</th>
                      <th className="text-left p-3">REPORTER</th>
                      <th className="text-left p-3">COMMENT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {abuseData.recentReports.map((report, i) => (
                      <tr key={i} className="border-b border-border/50 hover:bg-muted/30">
                        <td className="p-3 text-muted-foreground whitespace-nowrap">
                          {new Date(report.reportedAt).toLocaleDateString()}
                        </td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {report.categories.map(cat => (
                              <span key={cat} className="px-1.5 py-0.5 rounded text-[10px] bg-destructive/20 text-destructive">
                                {CATEGORY_NAMES[cat] || `Cat ${cat}`}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="p-3 text-muted-foreground">{report.reporterCountryCode}</td>
                        <td className="p-3 text-foreground/70 max-w-[300px] truncate">{report.comment || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Local threat history */}
          {threats.length > 0 && (
            <div className="bg-card/80 border border-border rounded-lg overflow-hidden">
              <div className="p-4 border-b border-border">
                <h3 className="text-sm font-mono text-primary uppercase tracking-wider">
                  Local Attack History ({threats.length} events)
                </h3>
              </div>
              <div className="overflow-auto max-h-[400px]">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="border-b border-border text-muted-foreground">
                      <th className="text-left p-3">PORT</th>
                      <th className="text-left p-3">TYPE</th>
                      <th className="text-left p-3">SEVERITY</th>
                      <th className="text-left p-3">TIME</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threats.map(event => (
                      <tr key={event.id} className="border-b border-border/50 hover:bg-muted/30">
                        <td className="p-3">{event.port}</td>
                        <td className="p-3">
                          <span className={cn(
                            'px-2 py-0.5 rounded text-[10px] uppercase',
                            event.type === 'ddos' || event.type === 'malware'
                              ? 'bg-destructive/20 text-destructive'
                              : 'bg-warning/20 text-warning'
                          )}>
                            {event.type.replace('_', ' ')}
                          </span>
                        </td>
                        <td className={cn('p-3',
                          event.severity === 'critical' ? 'text-destructive' :
                          event.severity === 'high' ? 'text-destructive/80' :
                          event.severity === 'medium' ? 'text-warning' :
                          'text-muted-foreground'
                        )}>
                          {event.severity}
                        </td>
                        <td className="p-3 text-muted-foreground">{new Date(event.created_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {!hasData && !loading && (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <Shield className="h-16 w-16 mb-4 opacity-20" />
          <p className="font-mono text-sm">Enter any IP address to get real threat intelligence</p>
          <p className="font-mono text-xs mt-2 text-muted-foreground/60">Powered by AbuseIPDB — real abuse reports from the global community</p>
        </div>
      )}
    </div>
  );
}
