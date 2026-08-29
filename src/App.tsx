import React, { useState } from 'react';
import { Sidebar } from './components/Sidebar';
import { Dashboard } from './components/Dashboard';
import { FindingsView } from './components/FindingsView';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  return (
    <div className="flex h-screen bg-slate-950 font-sans">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      {activeTab === 'dashboard' ? (
        <Dashboard />
      ) : activeTab === 'findings' ? (
        <FindingsView />
      ) : (
        <div className="flex-1 flex items-center justify-center text-slate-500">
          <div className="text-center">
            <h2 className="text-xl font-medium mb-2 text-slate-300">Coming Soon</h2>
            <p>The {activeTab} view is currently under development.</p>
          </div>
        </div>
      )}
    </div>
  );
}


