import React, { useRef, useEffect } from 'react';
import { Icons } from './Icons';
import type { LogEntry } from '../../types';

interface TerminalDrawerProps {
  logs: LogEntry[];
  loading: boolean;
  onClear: () => void;
}

export const TerminalDrawer: React.FC<TerminalDrawerProps> = ({ logs, loading, onClear }) => {
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when logs change
  useEffect(() => { 
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" }); 
  }, [logs]);

  return (
    <div className="terminal-drawer" style={{ transform: loading || logs.length > 0 ? 'translateY(0)' : 'translateY(100%)' }}>
      <div className="terminal-header" onClick={onClear}>
        <span>System Logs (Click to clear)</span>
        <Icons.ChevronDown />
      </div>
      <div className="terminal-content">
        {logs.map((l, i) => <div key={i} className={`log-entry ${l.type}`}>[{l.timestamp}] {l.msg}</div>)}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
};