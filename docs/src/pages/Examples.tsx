import Code from '../components/Code';

const EXAMPLES: { title: string; blurb: string; lang: string; code: string }[] = [
  {
    title: 'Linux, non-root, fully offline',
    blurb: 'The default posture: unprivileged scan, zero network, one sealed report.',
    lang: 'bash',
    code: `# copy the issued extractor to the target any way you like
./hbs-extractor --no-elevate --quiet

# exit 0; hbs-report-*.hbs sits beside the binary
# deliver it via USB drop / dashboard upload`,
  },
  {
    title: 'Air-gapped push over a jump host',
    blurb: 'Let the extractor deliver the report itself — the only time it uses the network.',
    lang: 'bash',
    code: `# token comes from the environment…
HBS_PUSH_TOKEN=<campaignPushToken> ./hbs-extractor \\
  --no-elevate --quiet --push https://dashboard.example/api/ingest

# …or from a read-only token file (mutually exclusive with the env var)
./hbs-extractor --push https://dashboard.example/api/ingest \\
  --push-token-file /etc/hbs/push.token`,
  },
  {
    title: 'Filtered re-scan of one category',
    blurb: 'Chase a specific finding without re-running the full catalog.',
    lang: 'bash',
    code: `# only the SSH family, written to a fixed path
./hbs-extractor --category SSH --no-elevate --quiet \\
  --out /tmp/ssh-followup.hbs

# or an explicit ID list
./hbs-extractor --only LIN-SSH-001,LIN-NET-004 --out /tmp/scan.hbs`,
  },
  {
    title: 'Windows scripted / CI run',
    blurb: 'No prompts, no pause, machine-readable output.',
    lang: 'powershell',
    code: `hbs-extractor.exe --no-elevate --no-pause --quiet
# admin-only controls need one consent:
hbs-extractor.exe --elevate
# denial still completes: remaining checks fall back read-only
# and unresolved results become DegradedPartial`,
  },
  {
    title: 'Create a campaign and issuance via API',
    blurb: 'Drive the dashboard programmatically; the session cookie authenticates.',
    lang: 'bash',
    code: `POST /api/campaigns                         { "name":"Acme Q3", "locations":[{"name":"DC-East"}] }
POST /api/campaigns/:id/locations/:loc/issuances   { "platform":"linux-amd64" }
GET  /api/issuances/:id/download?token=<downloadToken>`,
  },
  {
    title: 'Batch upload a fleet of reports',
    blurb: 'Collected offline by USB? Drop them all at once.',
    lang: 'text',
    code: `# Campaign → Locations & Hosts → drag up to 32 .hbs files
# into the drop zone.
#
# The dashboard decrypts, verifies, routes each host by
# machine-id, and auto-resolves findings that now pass on
# re-scans. SSE /api/events fires report-arrived per file.`,
  },
];

export default function Examples() {
  return (
    <div className="mx-auto max-w-[1280px] px-6 py-10">
      <p className="mono-label">Examples</p>
      <h1 className="mt-2 text-3xl font-extrabold text-white">Real workflows, copy and run</h1>
      <p className="mt-2 max-w-[720px] text-muted">
        Every recipe below reflects the extractor and dashboard as they actually behave today.
      </p>
      <div className="mt-8 grid gap-4 lg:grid-cols-2">
        {EXAMPLES.map((ex) => (
          <div key={ex.title} className="glass-card !gap-2">
            <h3 className="text-[1.0em] font-bold text-white">{ex.title}</h3>
            <p className="text-[0.84em] text-muted">{ex.blurb}</p>
            <Code content={ex.code} lang={ex.lang} />
          </div>
        ))}
      </div>
    </div>
  );
}
