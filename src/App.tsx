import React, { useState } from 'react';

import { Dashboard } from './components/Dashboard';
import { DevicesView } from './components/DevicesView';
import { FindingsView } from './components/FindingsView';
import { HistoryView } from './components/HistoryView';
import { PrivacyView } from './components/PrivacyView';
import { SettingsView } from './components/SettingsView';
import { Sidebar } from './components/Sidebar';
import { TimelineView } from './components/TimelineView';
import { useScan } from './hooks/useScan';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  // Set when a dashboard tile is opened, so Findings arrives filtered to
  // that area rather than showing everything and leaving the user to look.
  const [focusCategory, setFocusCategory] = useState<string | null>(null);

  // One scan drives every view, so the sidebar, dashboard and findings list can
  // never disagree about what was found.
  const scan = useScan();

  return (
    <div className="flex h-screen bg-slate-950 font-sans">
      <Sidebar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setFocusCategory(null);
          setActiveTab(tab);
        }}
        scan={scan}
      />

      {activeTab === 'dashboard' ? (
        <Dashboard
          scan={scan}
          onOpenCategory={(category) => {
            setFocusCategory(category);
            setActiveTab('findings');
          }}
        />
      ) : activeTab === 'findings' ? (
        <FindingsView
          scan={scan}
          focusCategory={focusCategory}
          onClearFocus={() => setFocusCategory(null)}
        />
      ) : activeTab === 'devices' ? (
        <DevicesView />
      ) : activeTab === 'timeline' ? (
        <TimelineView />
      ) : activeTab === 'history' ? (
        <HistoryView />
      ) : activeTab === 'privacy' ? (
        <PrivacyView />
      ) : activeTab === 'settings' ? (
        <SettingsView />
      ) : (
        <div className="flex-1 flex items-center justify-center text-slate-500">
          <div className="text-center max-w-md px-8">
            <h2 className="text-xl font-medium mb-2 text-slate-300">Not built yet</h2>
            <p>
              The {activeTab} view has no backend behind it. Rather than show you placeholder
              figures, SENTRY shows nothing until the checks are real.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
