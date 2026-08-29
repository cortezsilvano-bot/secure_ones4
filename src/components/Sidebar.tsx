import React from 'react';
import { Shield, LayoutDashboard, AlertTriangle, Monitor, Clock, History, Lock, Settings, HelpCircle, Activity } from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export function Sidebar({ activeTab, setActiveTab }: SidebarProps) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'findings', label: 'Findings', icon: AlertTriangle },
    { id: 'devices', label: 'Devices', icon: Monitor },
    { id: 'timeline', label: 'Timeline', icon: Clock },
    { id: 'history', label: 'History', icon: History },
    { id: 'privacy', label: 'Privacy', icon: Lock },
  ];

  const bottomItems = [
    { id: 'settings', label: 'Settings', icon: Settings },
    { id: 'help', label: 'Help', icon: HelpCircle },
  ];

  return (
    <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen text-slate-300">
      <div className="p-6 flex items-center gap-3 text-white mb-2">
        <div className="bg-blue-600/20 p-1.5 rounded-lg border border-blue-500/30">
          <Shield className="w-6 h-6 text-blue-500" />
        </div>
        <span className="font-semibold text-lg tracking-wide">SENTRY</span>
      </div>

      <nav className="flex-1 px-4 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                isActive 
                  ? 'bg-blue-600/10 text-blue-400 font-medium' 
                  : 'hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <Icon className={`w-5 h-5 ${isActive ? 'text-blue-500' : 'text-slate-400'}`} />
              {item.label}
            </button>
          );
        })}
      </nav>

      <div className="px-4 py-6 space-y-4">
        {/* Scan Status Box */}
        <div className="bg-slate-800/40 rounded-xl p-4 border border-slate-700/50">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
            <span className="text-sm font-medium text-slate-200">Scan status</span>
          </div>
          <div className="text-sm text-slate-400 mb-1">All systems healthy</div>
          <div className="text-xs text-slate-500 mb-3">Last scan: 8:32 AM</div>
          <button className="text-sm text-blue-400 hover:text-blue-300 transition-colors">
            View details
          </button>
        </div>

        <nav className="space-y-1">
          {bottomItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors hover:bg-slate-800/50 hover:text-slate-200`}
              >
                <Icon className="w-5 h-5 text-slate-400" />
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>
    </div>
  );
}
