import { describe, test, expect } from 'vitest';
import CryptoJS from 'crypto-js';

describe('Aegis Forensics Engine, Date Window Filters and Defanger', () => {
  // Test defanger logic
  const defangString = (text: string): string => {
    return text
      .replace(/http:\/\//gi, 'hxxp://')
      .replace(/https:\/\//gi, 'hxxps://')
      .replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/g, '$1[.]2[.]3[.]4'.replace(/2/, '$2').replace(/3/, '$3').replace(/4/, '$4'))
      .replace(/(\w+)\.(com|org|net|ru|cn|io)/gi, '$1[.]$2');
  };

  test('Defanger should safely neutralize malicious URLs and IP addresses', () => {
    const rawUrl = "http://malicious-c2.com/payload.sh";
    const rawIp = "192.168.1.100";
    
    const defangedUrl = defangString(rawUrl);
    const defangedIp = defangString(rawIp);

    expect(defangedUrl).toContain("hxxp://");
    expect(defangedUrl).toContain("malicious-c2[.]com");
    expect(defangedIp).toEqual("192[.]168[.]1[.]100");
  });

  test('Date range filter should correctly partition timestamps', () => {
    const now = Date.now();
    const incidentOneHourAgo = new Date(now - 30 * 60 * 1000).toISOString(); // 30 mins ago
    const incidentYesterday = new Date(now - 25 * 3600 * 1000).toISOString(); // 25 hours ago
    const incidentLastMonth = new Date(now - 35 * 86400 * 1000).toISOString(); // 35 days ago

    const filterLast1H = (iso: string) => (now - new Date(iso).getTime()) <= 3600 * 1000;
    const filterLast24H = (iso: string) => (now - new Date(iso).getTime()) <= 24 * 3600 * 1000;
    const filterLast30D = (iso: string) => (now - new Date(iso).getTime()) <= 30 * 86400 * 1000;

    expect(filterLast1H(incidentOneHourAgo)).toBe(true);
    expect(filterLast1H(incidentYesterday)).toBe(false);

    expect(filterLast24H(incidentOneHourAgo)).toBe(true);
    expect(filterLast24H(incidentYesterday)).toBe(false);

    expect(filterLast30D(incidentYesterday)).toBe(true);
    expect(filterLast30D(incidentLastMonth)).toBe(false);
  });

  test('Cryptographic Evidence Seal (SHA-256) should remain deterministic and tamper-evident', () => {
    const payload = "syscall=setuid ppid=1209 pid=31411 comm=backdoor_payload args=uid=0(root)";
    const timestamp = "2026-10-20T12:00:00Z";

    const originalSeal = CryptoJS.SHA256(payload + timestamp).toString();
    const verifySeal = CryptoJS.SHA256(payload + timestamp).toString();
    expect(originalSeal).toEqual(verifySeal);

    // Tampering test: altering even one byte changes the seal completely
    const tamperedPayload = "syscall=setuid ppid=1209 pid=31411 comm=backdoor_payload args=uid=1000(user)";
    const tamperedSeal = CryptoJS.SHA256(tamperedPayload + timestamp).toString();
    expect(tamperedSeal).not.toEqual(originalSeal);
  });

  test('CEF standard log line structure validation', () => {
    const threat = {
      id: "arch-001",
      name: "eBPF Root Escalation SUID Attempt",
      severity: "high",
      status: "Unresolved",
      details: "Process backdoor_payload triggered setuid",
      rawPayload: "syscall=setuid",
      category: "ebpf"
    };

    const sevNumber = threat.severity === 'high' ? 9 : 3;
    const cefLine = `CEF:0|Aegis-Security|Kernel-VMM|2.5.0|${threat.id}|${threat.name}|${sevNumber}|cat=${threat.category} cs1=${threat.status}`;

    expect(cefLine.startsWith("CEF:0|Aegis-Security|Kernel-VMM|2.5.0")).toBe(true);
    expect(cefLine).toContain("arch-001");
    expect(cefLine).toContain("|9|");
  });
});
