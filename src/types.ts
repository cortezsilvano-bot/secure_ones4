export type Severity = 'Safe' | 'Attention' | 'Warning' | 'Critical';
export type FindingStatus = 'open' | 'resolved' | 'dismissed' | 'allowlisted';

export interface Finding {
  id: string;
  correlation_id: string;
  category: string;
  severity: Severity;
  confidence: number; // 0..1
  what_happened: string;
  why_it_matters: string;
  device_ref?: string;
  evidence: string[];
  recommended_action?: string;
  auto_fix?: boolean;
  first_seen: string;
  last_seen: string;
  status: FindingStatus;
}

export interface OverviewItem {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  message: string;
  lastChecked: string;
}

export interface SecurityScore {
  score: number;
  status: Severity;
  message: string;
  subMessage: string;
  lastScan: string;
  nextScan: string;
}
