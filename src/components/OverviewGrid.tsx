import React from 'react';
import { Shield, Monitor, Wifi, Router, Users, Bug, ShieldAlert, RotateCcw, ArrowRightToLine } from 'lucide-react';
import { OverviewItem } from '../types';
import { SeverityIcon } from './SeverityBadge';

interface OverviewGridProps {
  items: OverviewItem[];
}

export function OverviewGrid({ items }: OverviewGridProps) {
  
  const getIcon = (category: string) => {
    switch (category) {
      case 'Desktop': return <Monitor className="w-6 h-6" />;
      case 'Network': return <Wifi className="w-6 h-6" />;
      case 'Router': return <Router className="w-6 h-6" />;
      case 'Devices': return <Users className="w-6 h-6" />;
      case 'Vulnerabilities': return <ShieldAlert className="w-6 h-6" />;
      case 'Malware': return <Bug className="w-6 h-6" />;
      case 'Firewall': return <Shield className="w-6 h-6" />;
      case 'Updates': return <RotateCcw className="w-6 h-6" />;
      case 'OpenPorts': return <ArrowRightToLine className="w-6 h-6" />;
      default: return <Shield className="w-6 h-6" />;
    }
  };

  return (
    <div className="grid grid-cols-3 gap-4">
      {items.map((item) => (
        <div key={item.id} className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-4 hover:bg-slate-800/50 transition-colors cursor-pointer group">
          <div className="flex items-start justify-between mb-3">
            <div className="text-slate-400 group-hover:text-slate-300 transition-colors">
              {getIcon(item.category)}
            </div>
            <div className="text-slate-500 opacity-0 group-hover:opacity-100 transition-opacity">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m9 18 6-6-6-6"/></svg>
            </div>
          </div>
          <h3 className="text-slate-200 font-medium text-sm mb-2">{item.title}</h3>
          
          <div className="flex items-center gap-2 mb-2">
            <SeverityIcon severity={item.severity} className="w-4 h-4" />
            <span className="text-slate-300 text-sm">{item.severity}</span>
          </div>
          
          <div className="text-slate-400 text-xs mb-3 h-4">{item.message}</div>
          <div className="text-slate-500 text-xs">Last checked {item.lastChecked}</div>
        </div>
      ))}
    </div>
  );
}
