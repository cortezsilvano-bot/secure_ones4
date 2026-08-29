import React from 'react';
import { Shield, Play } from 'lucide-react';
import { SeverityBadge } from './SeverityBadge';
import { OverviewGrid } from './OverviewGrid';
import { CircularProgress } from './CircularProgress';
import { mockSecurityScore, mockFindings, mockOverviewItems } from '../data';

export function Dashboard() {
  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-8">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Header */}
        <div className="flex items-end justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-white mb-1">SENTRY</h1>
            <p className="text-slate-400 text-sm">Your home security at a glance</p>
          </div>
          <div className="flex items-center gap-6">
            <div className="text-right">
              <div className="text-xs text-slate-500 mb-0.5">Last scan</div>
              <div className="text-sm text-slate-300">{mockSecurityScore.lastScan}</div>
            </div>
            <div className="text-right">
              <div className="text-xs text-slate-500 mb-0.5">Next scan</div>
              <div className="text-sm text-slate-300">{mockSecurityScore.nextScan}</div>
            </div>
            <button className="bg-blue-600 hover:bg-blue-500 text-white px-5 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors">
              <Shield className="w-4 h-4" />
              Scan now
            </button>
          </div>
        </div>

        {/* Top Section: Score & Alerts */}
        <div className="grid grid-cols-12 gap-6">
          {/* Security Score Card */}
          <div className="col-span-4 bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6 relative overflow-hidden flex flex-col">
             <div className="absolute top-4 right-4 text-slate-500 hover:text-slate-300 cursor-pointer">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
            </div>
            <h2 className="text-slate-200 font-medium mb-6">Home Security Score</h2>
            <div className="flex items-center gap-6 flex-1">
              <CircularProgress score={mockSecurityScore.score} />
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <SeverityBadge severity={mockSecurityScore.status} />
                </div>
                <p className="text-sm text-slate-300 mb-4">{mockSecurityScore.subMessage}</p>
                <div className="text-xs text-slate-500 space-y-1">
                  <p>Last full scan: {mockSecurityScore.lastScan}</p>
                  <p>Next scheduled scan: {mockSecurityScore.nextScan}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Things worth checking */}
          <div className="col-span-8">
            <h2 className="text-slate-200 font-medium mb-4">Things worth checking</h2>
            <div className="grid grid-cols-3 gap-4 h-[216px]">
              {mockFindings.map((finding, idx) => (
                <div key={finding.id} className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-5 flex flex-col">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700">
                        {idx + 1}
                      </div>
                    </div>
                  </div>
                  <h3 className="text-slate-200 font-medium text-sm mb-2">{finding.what_happened}</h3>
                  <p className="text-slate-400 text-xs flex-1">{finding.why_it_matters}</p>
                  <div className="flex items-center justify-between mt-4">
                    <SeverityBadge severity={finding.severity} />
                    <button className="text-slate-300 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border border-slate-700">
                      {finding.severity === 'Safe' ? 'View details' : 'Review'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Bottom Section: Overview & Status */}
        <div className="grid grid-cols-12 gap-6">
          <div className="col-span-8 space-y-4">
            <h2 className="text-slate-200 font-medium">Security overview</h2>
            <OverviewGrid items={mockOverviewItems} />
          </div>
          <div className="col-span-4 space-y-4">
            <div className="h-8"></div> {/* Spacer for alignment */}
            <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6 h-full">
               <div className="flex flex-col items-center justify-center text-center mb-8 mt-4">
                  <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center border border-emerald-500/20 mb-4">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" className="text-emerald-500" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m9 11 3 3L22 4"/></svg>
                  </div>
                  <h3 className="text-white font-medium mb-1">Everything looks good</h3>
                  <p className="text-slate-400 text-sm">No security issues need your attention.</p>
               </div>
               
               <div className="space-y-3 mb-8">
                 <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">SENTRY checked:</div>
                 {['Malware', 'Firewall', 'Network devices', 'Open ports', 'Software updates', 'Router configuration'].map(item => (
                    <div key={item} className="flex items-center gap-2 text-sm text-slate-300">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" className="text-emerald-500" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
                      {item}
                    </div>
                 ))}
               </div>

               <div className="space-y-2 mb-6">
                 <div className="flex justify-between text-sm">
                   <span className="text-slate-500">Last scan:</span>
                   <span className="text-slate-300">{mockSecurityScore.lastScan}</span>
                 </div>
                 <div className="flex justify-between text-sm">
                   <span className="text-slate-500">Next scan:</span>
                   <span className="text-slate-300">{mockSecurityScore.nextScan}</span>
                 </div>
               </div>

               <div className="space-y-3">
                 <button className="w-full bg-blue-600 hover:bg-blue-500 text-white px-4 py-2.5 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors">
                    <Play className="w-4 h-4 fill-current" />
                    Run another scan
                 </button>
                 <button className="w-full bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors">
                    View scan details
                 </button>
               </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
