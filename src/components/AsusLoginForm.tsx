import React from 'react';
import type { AsusLoginOptions } from '../services/ipc';

export function AsusLoginForm({ address, submit }: {
  address: string;
  submit: (options: AsusLoginOptions) => void;
}) {
  return <details className="w-full text-xs text-slate-300 rounded border border-slate-700 p-3">
    <summary className="cursor-pointer">ASUS settings scan (experimental)</summary>
    <form className="mt-3 grid gap-3" autoComplete="off" onSubmit={(event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const fields = new FormData(form);
      const options: AsusLoginOptions = {
        username: String(fields.get('username') ?? ''),
        password: String(fields.get('password') ?? ''),
        httpsPort: Number(fields.get('port')),
        certificatePem: String(fields.get('certificate') ?? ''),
        supportRegion: (fields.get('region') ?? 'unknown') as AsusLoginOptions['supportRegion'],
      };
      form.reset();
      submit(options);
    }}>
      <p>For RT-AX82U / RT-AX82U V2 on GNUton 3004.388.9_2-gnuton1 in router mode.
        Reads firmware identity, IPv4/IPv6 firewall, WAN web-management and wireless settings.
        Hardware compatibility has not been tested.</p>
      <p>This sends one login to {address}, followed by settings reads and logout.
        Login can affect existing admin sessions and failed-login counters. No retries or
        configuration changes are requested. Wireless checks enumerate this router's declared local
        interfaces, including guest networks, and read their settings. AiMesh nodes and negotiated
        client encryption are outside this scan. CVE and lifecycle checks use dated, reviewed public evidence.</p>
      <label>Router sales/support region (for ASUS lifecycle matching)
        <select name="region" defaultValue="unknown" className="block bg-slate-900 border border-slate-600 rounded p-2">
          <option value="unknown">Unknown</option><option value="eu">European Union</option><option value="other">Outside the European Union</option>
        </select>
      </label>
      <label>HTTPS port
        <input name="port" type="number" min="1" max="65535" defaultValue="8443" required
          className="block bg-slate-900 border border-slate-600 rounded p-2" />
      </label>
      <label>Router admin username
        <input name="username" maxLength={128} required autoComplete="off" spellCheck={false}
          className="block w-full bg-slate-900 border border-slate-600 rounded p-2" />
      </label>
      <label>Router admin password
        <input name="password" type="password" maxLength={128} required autoComplete="off"
          className="block w-full bg-slate-900 border border-slate-600 rounded p-2" />
      </label>
      <label>Trusted public PEM certificate (optional)
        <textarea name="certificate" maxLength={16384} rows={3} spellCheck={false}
          className="block w-full bg-slate-900 border border-slate-600 rounded p-2 font-mono" />
      </label>
      <p>Use a certificate you obtained and verified independently. It is trusted for this scan only;
        its validity and the gateway IP must still verify. Never paste a private key.
        With this field empty, standard public certificate roots are used. Invalid TLS is rejected.</p>
      <p>Credentials are sent only to the selected gateway over verified HTTPS and are not saved.
        The form clears on submission. Application and library memory copies cannot be guaranteed erased.
        A cancelled scan may leave the router session active until it expires.</p>
      <label className="flex gap-2 items-start"><input type="checkbox" required />
        I confirm this model/build and approve one login and settings scan of {address},
        including use of the certificate above if supplied.
      </label>
      <div className="flex gap-4">
        <button type="reset" className="underline">Clear credentials</button>
        <button type="submit" className="text-amber-300 underline">Confirm ASUS settings scan</button>
      </div>
    </form>
  </details>;
}
