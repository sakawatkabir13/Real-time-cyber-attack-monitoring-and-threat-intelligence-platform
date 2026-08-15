import { useEffect, useState, useRef } from 'react';
import { UploadCloud, FileText, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export default function LogAnalyzerPage() {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [status, setStatus] = useState<'idle' | 'uploading' | 'analyzing' | 'done' | 'error'>('idle');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  useEffect(() => {
    if (status !== 'analyzing') return;
    let cancelled = false;
    const poll = async () => {
      try {
        const response = await fetch('/api/analysis-status');
        if (!response.ok) throw new Error('Could not read analysis status');
        const result = await response.json();
        if (cancelled) return;
        if (result.state === 'complete') setStatus('done');
        if (result.state === 'error') setStatus('error');
      } catch {
        if (!cancelled) setStatus('error');
      }
    };
    poll();
    const timer = window.setInterval(poll, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [status]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setStatus('idle');
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
      setStatus('idle');
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setIsUploading(true);
    setStatus('uploading');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/analyze-log-file', {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        throw new Error('Failed to upload file');
      }

      setStatus('analyzing');
      toast({
        title: 'Analysis Started',
        description: 'The log file is being processed. Head to the Dashboard to watch the replay!',
        variant: 'default',
      });
      
    } catch (e) {
      setStatus('error');
      toast({
        title: 'Upload Failed',
        description: 'An error occurred while uploading the log file.',
        variant: 'destructive',
      });
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="p-8 h-full flex flex-col">
      <h1 className="text-2xl font-bold font-display text-primary mb-2 text-glow">Log Analyzer</h1>
      <p className="text-muted-foreground font-mono text-sm mb-8 max-w-2xl">
        Upload your Nginx or Apache access logs to simulate historical traffic. The backend will process each line through the ML Engine and replay the events onto your dashboard perfectly in real-time.
      </p>

      <div className="flex-1 max-w-3xl">
        <div
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-lg p-12 flex flex-col items-center justify-center transition-colors
            ${file ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50 hover:bg-muted/50'}
          `}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
            accept=".log,.txt"
          />

          {!file ? (
            <>
              <UploadCloud className="w-16 h-16 text-muted-foreground mb-4" />
              <h3 className="text-lg font-mono font-bold text-slate-200 mb-2">Drag & Drop Access Logs</h3>
              <p className="text-sm text-muted-foreground mb-6">or click below to browse</p>
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-6 py-2 bg-primary/20 text-primary hover:bg-primary/30 rounded-md font-mono text-sm border border-primary/50 transition-colors glow-primary"
              >
                Select File
              </button>
            </>
          ) : (
            <>
              <FileText className="w-16 h-16 text-primary mb-4" />
              <h3 className="text-lg font-mono font-bold text-slate-200 mb-2">{file.name}</h3>
              <p className="text-sm text-muted-foreground mb-6">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
              
              <div className="flex gap-4">
                <button
                  onClick={() => { setFile(null); setStatus('idle'); }}
                  disabled={isUploading}
                  className="px-6 py-2 bg-muted text-muted-foreground hover:bg-muted/80 rounded-md font-mono text-sm transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleUpload}
                  disabled={isUploading}
                  className="px-6 py-2 bg-primary text-primary-foreground hover:bg-primary/90 rounded-md font-mono text-sm shadow-[0_0_15px_rgba(0,243,255,0.4)] transition-all"
                >
                  {isUploading ? 'Uploading...' : 'Analyze Logs'}
                </button>
              </div>
            </>
          )}
        </div>

        {status === 'analyzing' && (
          <div className="mt-8 p-4 bg-primary/10 border border-primary/30 rounded-lg flex items-center gap-4">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary" />
            <div>
              <p className="text-sm font-bold text-primary">Analysis in Progress...</p>
              <p className="text-xs text-muted-foreground font-mono">The log file is being replayed to the Dashboard.</p>
            </div>
          </div>
        )}

        {status === 'done' && (
          <div className="mt-8 p-4 bg-success/10 border border-success/30 rounded-lg flex items-center gap-4">
            <CheckCircle2 className="h-6 w-6 text-success" />
            <div>
              <p className="text-sm font-bold text-success">Upload Complete</p>
              <p className="text-xs text-muted-foreground font-mono">Go to the Dashboard to watch the threat simulation.</p>
            </div>
          </div>
        )}
        
        {status === 'error' && (
          <div className="mt-8 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-4">
            <AlertCircle className="h-6 w-6 text-destructive" />
            <div>
              <p className="text-sm font-bold text-destructive">Upload Error</p>
              <p className="text-xs text-muted-foreground font-mono">Failed to upload or parse the log file.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
