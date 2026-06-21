import { motion } from 'motion/react';
import { ShieldCheck, Cpu, HardDrive, Bell, AlertTriangle, Radio } from 'lucide-react';
import { useState, useEffect } from 'react';

interface ConsoleHeaderProps {
  threatLevel: 'low' | 'medium' | 'high';
  setThreatLevel: (level: 'low' | 'medium' | 'high') => void;
  activeInterceptsCount: number;
}

export default function ConsoleHeader({ threatLevel, setThreatLevel, activeInterceptsCount }: ConsoleHeaderProps) {
  const [cpuLoad, setCpuLoad] = useState(24);
  const [ramUsage, setRamUsage] = useState(48);
  const [timeStr, setTimeStr] = useState('10:45:05 UTC');

  useEffect(() => {
    const timer = setInterval(() => {
      // Dynamic fluctuating CPU load
      setCpuLoad(prev => {
        const delta = Math.floor(Math.random() * 11) - 5;
        const next = prev + delta;
        return Math.max(12, Math.min(88, next));
      });
      // Dynamic fluctuating RAM load
      setRamUsage(prev => {
        const delta = Math.floor(Math.random() * 5) - 2;
        const next = prev + delta;
        return Math.max(45, Math.min(54, next));
      });
      
      const now = new Date();
      setTimeStr(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    }, 1500);

    return () => clearInterval(timer);
  }, []);

  const getThreatColor = () => {
    switch (threatLevel) {
      case 'low': return 'text-emerald-400 bg-white/[0.02] border-white/5 shadow-[rgba(16,185,129,0.05)_0px_0px_10px]';
      case 'medium': return 'text-[#D4AF37] bg-white/[0.02] border-white/5 shadow-[rgba(212,175,55,0.05)_0px_0px_10px]';
      case 'high': return 'text-rose-400 bg-rose-950/20 border-rose-950/80 shadow-[rgba(244,63,94,0.05)_0px_0px_10px]';
    }
  };

  return (
    <div id="console-header" className="grid grid-cols-1 md:grid-cols-4 gap-4 p-5 border-b border-white/5 bg-[#080809] select-none">
      {/* Brand & Systems Status */}
      <div className="flex flex-col justify-between border border-white/5 p-4 bg-black/20 rounded">
        <div className="flex items-center gap-3">
          <div className="w-2.5 h-2.5 rounded-full bg-[#D4AF37] shadow-[0_0_8px_rgba(212,175,55,0.6)] animate-pulse" />
          <h1 className="font-serif text-sm font-light tracking-[0.25em] text-zinc-100 uppercase">
            Aegis Unified Suite
          </h1>
        </div>
        <div className="flex items-center justify-between mt-4 text-[10px] tracking-wider uppercase font-mono">
          <span className="text-white/30">ENGINE STATUS:</span>
          <span className="text-emerald-400 flex items-center gap-1 font-semibold">
            <Radio size={12} className="animate-spin duration-3000" /> ACTIVE
          </span>
        </div>
        <div className="text-[9px] uppercase tracking-wider font-mono text-white/20 mt-1">
          SYS TIME: {timeStr}
        </div>
      </div>

      {/* Sys Telemetry Indicators */}
      <div className="grid grid-cols-2 gap-3 border border-white/5 p-4 bg-black/20 rounded">
        <div className="flex flex-col justify-between">
          <div className="flex items-center gap-1.5 text-white/40 text-[10px] uppercase font-mono tracking-wider">
            <Cpu size={13} className="text-white/30" /> CPU LOAD
          </div>
          <div className="text-lg font-mono font-light text-zinc-200 mt-1">
            {cpuLoad}%
          </div>
          <div className="w-full bg-white/5 h-1 rounded-full overflow-hidden mt-1">
            <motion.div 
              className="bg-[#D4AF37] h-full"
              animate={{ width: `${cpuLoad}%` }}
              transition={{ duration: 1 }}
            />
          </div>
        </div>

        <div className="flex flex-col justify-between">
          <div className="flex items-center gap-1.5 text-white/40 text-[10px] uppercase font-mono tracking-wider">
            <HardDrive size={13} className="text-white/30" /> MEMORY
          </div>
          <div className="text-lg font-mono font-light text-zinc-200 mt-1 border-white/0">
            {ramUsage}%
          </div>
          <div className="w-full bg-white/5 h-1 rounded-full overflow-hidden mt-1">
            <motion.div 
              className="bg-white/40 h-full"
              animate={{ width: `${ramUsage}%` }}
              transition={{ duration: 0.8 }}
            />
          </div>
        </div>
      </div>

      {/* Operation State & Threats */}
      <div className={`border p-4 rounded flex flex-col justify-between transition-colors duration-300 ${getThreatColor()}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-[10px] font-mono tracking-wider uppercase">
            <ShieldCheck size={13} /> DEFENSE POSTURE
          </div>
          {threatLevel === 'high' && (
            <AlertTriangle size={13} className="animate-bounce" />
          )}
        </div>
        
        <div className="flex gap-1.5 mt-2.5">
          {(['low', 'medium', 'high'] as const).map(lev => (
            <button
              key={lev}
              id={`posture-btn-${lev}`}
              onClick={() => setThreatLevel(lev)}
              className={`flex-1 py-1 text-[9px] tracking-wider font-mono font-bold uppercase rounded border transition-all cursor-pointer ${
                threatLevel === lev 
                ? 'bg-[#D4AF37]/90 text-black border-[#D4AF37] shadow-[0_0_8px_rgba(212,175,55,0.3)]'
                : 'bg-black/40 text-white/40 border-white/5 hover:border-white/10 hover:text-white/80'
              }`}
            >
              {lev}
            </button>
          ))}
        </div>
      </div>

      {/* Alert Dispatch Matrix */}
      <div className="border border-white/5 p-4 bg-black/20 rounded flex flex-col justify-between">
        <div className="flex items-center justify-between text-white/40 text-[10px] uppercase font-mono tracking-wider">
          <span className="flex items-center gap-1.5"><Bell size={12} /> INTERCEPT LOG</span>
          <span className="flex h-1.5 w-1.5 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-rose-500"></span>
          </span>
        </div>
        
        <div className="flex items-center justify-between mt-2.5">
          <div className="flex flex-col">
            <span className="text-[9px] text-white/30 uppercase tracking-wider font-mono">BLOCKED SYSCALLS</span>
            <span className={`text-xl font-mono font-light ${activeInterceptsCount > 0 ? 'text-rose-400' : 'text-zinc-400'}`}>
              {activeInterceptsCount}
            </span>
          </div>
          <div className="text-[9px] uppercase tracking-wider font-mono text-white/40 border border-white/5 bg-black/30 px-2.5 py-1 rounded max-w-[130px] truncate">
            {activeInterceptsCount > 0 ? '⚠️ Violations' : '✓ Clean Exec'}
          </div>
        </div>
      </div>
    </div>
  );
}
