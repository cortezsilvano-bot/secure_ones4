import React from 'react';
import { FindingCard } from './FindingCard';
import { mockFindings } from '../data';

export function FindingsView() {
  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-white mb-2">Findings</h1>
          <p className="text-slate-400">Review and resolve security alerts across your network.</p>
        </div>

        <div className="space-y-4">
          {mockFindings.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      </div>
    </div>
  );
}
