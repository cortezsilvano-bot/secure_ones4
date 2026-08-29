import { Finding, OverviewItem, SecurityScore } from './types';

export const mockSecurityScore: SecurityScore = {
  score: 92,
  status: 'Safe',
  message: 'Safe',
  subMessage: 'Your PC and home network look healthy.',
  lastScan: 'Today, 8:32 AM',
  nextScan: 'Tomorrow, 8:00 AM',
};

export const mockFindings: Finding[] = [
  {
    id: 'FND-8821',
    correlation_id: 'c-1',
    category: 'Network Config',
    severity: 'Critical',
    confidence: 1.0,
    what_happened: 'SMBv1 protocol is enabled',
    why_it_matters: 'SMBv1 is a legacy protocol vulnerable to self-propagating ransomware like WannaCry. It should be disabled on all modern networks.',
    evidence: [
      'Registry Key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters',
      'Value Name: SMB1',
      'Value Data: 1 (Enabled)',
      'Verified via: WMI query'
    ],
    recommended_action: 'Disable the SMBv1 protocol in Windows Features or Registry.',
    auto_fix: true,
    first_seen: '2026-08-27T10:15:00Z',
    last_seen: '2026-08-28T08:32:00Z',
    status: 'open',
  },
  {
    id: 'FND-7392',
    correlation_id: 'c-2',
    category: 'Software Update',
    severity: 'Warning',
    confidence: 0.95,
    what_happened: '7-Zip is out of date',
    why_it_matters: 'Updating it closes a known security weakness (CVE-2023-XXXX). Attackers can exploit this by sending you a malicious archive file.',
    evidence: [
      'Path: C:\\Program Files\\7-Zip\\7z.exe',
      'Detected Version: 21.07',
      'Required Version: >= 23.01',
      'Matched CPE: cpe:2.3:a:7-zip:7-zip:21.07:*:*:*:*:*:*:*'
    ],
    recommended_action: 'Download and install the latest version of 7-Zip from the official website.',
    auto_fix: false,
    first_seen: '2026-08-28T08:32:00Z',
    last_seen: '2026-08-28T08:32:00Z',
    status: 'open',
  },
  {
    id: 'FND-6104',
    correlation_id: 'c-3',
    category: 'Network Device',
    severity: 'Attention',
    confidence: 0.7,
    what_happened: 'A new device joined your network',
    why_it_matters: 'We have not seen this device before. Ensure this is a device you own and recognize.',
    evidence: [
      'MAC Address: 00:1A:2B:3C:4D:5E',
      'IP Address: 192.168.1.145',
      'Vendor (OUI): Espressif Inc.',
      'Fingerprint match: IoT Device'
    ],
    recommended_action: 'Review the device and mark it as Trusted if recognized.',
    auto_fix: false,
    first_seen: '2026-08-28T08:32:00Z',
    last_seen: '2026-08-28T08:32:00Z',
    status: 'open',
  },
  {
    id: 'FND-4091',
    correlation_id: 'c-4',
    category: 'Malware',
    severity: 'Safe',
    confidence: 1.0,
    what_happened: 'Suspicious file detected and quarantined',
    why_it_matters: 'A downloaded file matched known malware signatures. The file was safely neutralized and cannot harm your PC.',
    evidence: [
      'Engine: YARA-X',
      'Rule matched: SUSP_File_EICAR_Test_Signature',
      'Path: C:\\Users\\user\\Downloads\\eicar.com',
      'SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      'Action taken: Encrypted and moved to quarantine store.'
    ],
    first_seen: '2026-08-26T14:20:00Z',
    last_seen: '2026-08-26T14:20:00Z',
    status: 'resolved',
  }
];

export const mockOverviewItems: OverviewItem[] = [
  { id: 'o-1', category: 'Desktop', title: 'Desktop', severity: 'Safe', message: 'No issues found', lastChecked: '8:32 AM' },
  { id: 'o-2', category: 'Network', title: 'Network', severity: 'Safe', message: 'Network is secure', lastChecked: '8:32 AM' },
  { id: 'o-3', category: 'Router', title: 'Router', severity: 'Safe', message: 'Router is configured well', lastChecked: '8:32 AM' },
  { id: 'o-4', category: 'Devices', title: 'Devices', severity: 'Attention', message: '14 trusted, 1 new', lastChecked: '8:32 AM' },
  { id: 'o-5', category: 'Vulnerabilities', title: 'Vulnerabilities', severity: 'Safe', message: 'No critical vulnerabilities', lastChecked: '8:32 AM' },
  { id: 'o-6', category: 'Malware', title: 'Malware', severity: 'Safe', message: 'No malware detected', lastChecked: '8:32 AM' },
  { id: 'o-7', category: 'Firewall', title: 'Firewall', severity: 'Safe', message: 'Firewall is active', lastChecked: '8:32 AM' },
  { id: 'o-8', category: 'Updates', title: 'Updates', severity: 'Warning', message: '2 updates available', lastChecked: '8:32 AM' },
  { id: 'o-9', category: 'OpenPorts', title: 'Open Ports', severity: 'Safe', message: 'No risky open ports', lastChecked: '8:32 AM' }
];
