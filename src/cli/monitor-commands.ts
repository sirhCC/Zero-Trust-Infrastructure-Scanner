import { Command } from 'commander';
import chalk from 'chalk';
import * as crypto from 'crypto';
import { RegisterCommands } from './shared';

export const registerMonitorCommands: RegisterCommands = (program: Command) => {
  program
    .command('monitor')
    .description('Real-time continuous security monitoring')
    .option('-p, --port <port>', 'WebSocket server port', '3001')
    .option('-i, --interval <seconds>', 'Monitoring interval in seconds', '30')
    .option('-t, --targets <targets>', 'Comma-separated list of targets to monitor')
    .option('--ws-token <token>', 'WebSocket auth token for clients')
    .option('--webhooks <urls>', 'Comma-separated webhook URLs for alerts')
    .option('--slack-webhook <url>', 'Slack webhook URL for notifications')
    .option('--teams-webhook <url>', 'Microsoft Teams webhook URL')
    .option('--email-alerts <emails>', 'Comma-separated email addresses for alerts')
    .action(async (options) => {
      console.log(chalk.blue('📡 Starting Real-Time Security Monitoring'));
      console.log(chalk.gray('WebSocket Port:'), options.port);
      console.log(chalk.gray('Scan Interval:'), `${options.interval}s`);
      try {
        const { RealTimeMonitor } = await import('../monitoring/real-time-monitor');
        const targets = options.targets
          ? options.targets.split(',').map((t: string) => t.trim())
          : ['localhost'];
        const webhooks = options.webhooks
          ? options.webhooks.split(',').map((w: string) => w.trim())
          : [];
        const emailAlerts = options.emailAlerts
          ? options.emailAlerts.split(',').map((e: string) => e.trim())
          : [];
        const monitorConfig = {
          scan_interval: parseInt(options.interval) * 1000,
          targets: targets.map((target: string) => ({
            id: `target-${target}`,
            name: target,
            scan_target: {
              type: 'network' as const,
              target: target,
              options: {
                cloud_provider: null,
                k8s_namespace: null,
                policy_file: null,
                scan_depth: 3,
              },
            },
            priority: 'medium' as const,
            enabled: true,
          })),
          alerting: {
            enabled: true,
            channels: [
              ...webhooks.map((url: string) => ({
                type: 'webhook' as const,
                config: { url },
                enabled: true,
              })),
              ...(options.slackWebhook
                ? [
                    {
                      type: 'slack' as const,
                      config: { webhook_url: options.slackWebhook },
                      enabled: true,
                    },
                  ]
                : []),
              ...(options.teamsWebhook
                ? [
                    {
                      type: 'teams' as const,
                      config: { webhook_url: options.teamsWebhook },
                      enabled: true,
                    },
                  ]
                : []),
              ...(emailAlerts.length > 0
                ? [
                    {
                      type: 'email' as const,
                      config: {
                        recipients: emailAlerts,
                        smtp: {
                          host: 'localhost',
                          port: 587,
                          secure: false,
                          auth: { user: '', pass: '' },
                        },
                      },
                      enabled: true,
                    },
                  ]
                : []),
            ],
            severity_threshold: 'medium' as const,
            rate_limiting: { max_alerts_per_minute: 5, cooldown_period: 300 },
          },
          websocket: {
            port: parseInt(options.port),
            path: '/ws',
            authentication: Boolean(options.wsToken),
            token: options.wsToken,
            max_connections: 100,
          },
          change_detection: {
            enabled: true,
            delta_threshold: 10,
            baseline_update_frequency: 24,
            ignore_transient_changes: true,
          },
        } as const;
        const monitor = new RealTimeMonitor(monitorConfig as any);
        console.log(chalk.green('✅ Real-time monitor initialized'));
        console.log(chalk.yellow('🔄 Starting continuous monitoring...'));
        await monitor.start();
        const httpStatus = await import('http');
        const statusServer = httpStatus.createServer((req: any, res: any) => {
          const allowHeaders = 'Content-Type, X-ZTIS-Token';
          const allowOrigin = '*';
          const allowMethods = 'GET, OPTIONS';
          const securityHeaders: Record<string, string> = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
          };
          try {
            if (req.method === 'OPTIONS') {
              res.writeHead(204, {
                'Access-Control-Allow-Origin': allowOrigin,
                'Access-Control-Allow-Methods': allowMethods,
                'Access-Control-Allow-Headers': allowHeaders,
              });
              res.end();
              return;
            }
            const url = new URL(req.url || '/', `http://localhost:${parseInt(options.port) + 1}`);
            if (url.pathname === '/api/status') {
              const expected = process.env.ZTIS_STATUS_TOKEN || process.env.ZTIS_WS_TOKEN || '';
              const provided =
                (req.headers['x-ztis-token'] as string) || url.searchParams.get('token') || '';
              if (expected && provided !== expected) {
                res.writeHead(401, {
                  'Content-Type': 'application/json',
                  'Access-Control-Allow-Origin': allowOrigin,
                  ...securityHeaders,
                });
                res.end(JSON.stringify({ ok: false, error: 'Unauthorized' }));
                return;
              }
              const stats = monitor.getMonitoringStats();
              res.writeHead(200, {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'Access-Control-Allow-Origin': allowOrigin,
                ...securityHeaders,
              });
              res.end(JSON.stringify({ ok: true, stats }));
              return;
            }
            res.writeHead(404, { 'Access-Control-Allow-Origin': allowOrigin, ...securityHeaders });
            res.end('Not found');
          } catch {
            res.writeHead(500, { 'Access-Control-Allow-Origin': allowOrigin, ...securityHeaders });
            res.end('Error');
          }
        });
        const statusPort = parseInt(options.port) + 1;
        statusServer.listen(statusPort, () => {
          console.log(
            chalk.blue(`📊 Status API listening on http://localhost:${statusPort}/api/status`)
          );
        });
        console.log(chalk.green('🚀 Monitoring active!'));
        console.log(chalk.blue(`📡 WebSocket server listening on port ${options.port}`));
        console.log(
          chalk.gray('📊 Dashboard WebSocket endpoint:'),
          chalk.cyan(`ws://localhost:${options.port}/ws`)
        );
        console.log(chalk.gray('⚡ Monitoring targets:'), targets.join(', '));
        console.log(chalk.yellow('🛑 Press Ctrl+C to stop monitoring'));

        const shutdown = async () => {
          console.log(chalk.yellow('\n🛑 Shutting down monitor...'));
          await monitor.stop();
          try {
            statusServer.close();
          } catch {
            /* ignore */
          }
          console.log(chalk.green('✅ Monitor stopped gracefully'));
          process.exit(0);
        };
        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
        setInterval(() => {
          /* keep alive */
        }, 1000);
      } catch (error: any) {
        console.error(chalk.red('❌ Monitor startup failed:'), error.message);
        process.exit(1);
      }
    });

  program
    .command('dashboard')
    .description('Launch web dashboard for real-time monitoring')
    .option('-p, --port <port>', 'Dashboard port', '3000')
    .option('--monitor-port <port>', 'WebSocket monitor port to connect to', '3001')
    .option('--ws-token <token>', 'WebSocket auth token to use when connecting')
    .action(async (options) => {
      console.log(chalk.blue('🌐 Starting Web Dashboard'));
      console.log(chalk.gray('Dashboard Port:'), options.port);
      console.log(chalk.gray('Monitor Port:'), options.monitorPort);
      try {
        const http = await import('http');
        const dashboardHtml = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Zero-Trust Scanner - Live Dashboard</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#0f172a;color:#e2e8f0}.header{background:#1e293b;padding:1rem;border-bottom:2px solid #334155}.header h1{color:#3b82f6;font-size:1.5rem}.header .status{color:#10b981;font-size:.9rem;margin-top:.5rem}.main{padding:2rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1.5rem}.card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.5rem}.card h3{color:#60a5fa;margin-bottom:1rem}.metric{display:flex;justify-content:space-between;margin-bottom:.5rem}.metric-value{font-weight:bold;color:#10b981}.events{max-height:400px;overflow-y:auto}.event{background:#374151;padding:.75rem;margin-bottom:.5rem;border-radius:4px;font-size:.85rem}.event.critical{border-left:4px solid #ef4444}.event.warning{border-left:4px solid #f59e0b}.event.info{border-left:4px solid #3b82f6}.timestamp{color:#9ca3af;font-size:.75rem}.connection-status{padding:.5rem 1rem;border-radius:4px;font-size:.9rem;margin-bottom:1rem}.connected{background:#065f46;color:#d1fae5}.disconnected{background:#7f1d1d;color:#fed7d7}.controls{display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:1rem;align-items:center}.btn{background:#3b82f6;color:#fff;border:none;padding:.4rem .8rem;border-radius:4px;cursor:pointer}.btn.secondary{background:#334155}.filters{display:flex;gap:1rem;align-items:center}.filters label{display:flex;gap:.4rem;align-items:center;font-size:.9rem}canvas{background:#0b1324;border-radius:6px;padding:6px}</style><script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script></head><body><div class="header"><h1>🛡️ Zero-Trust Infrastructure Scanner - Live Dashboard</h1><div class="status" id="status">Connecting to monitor...</div></div><div class="main"><div id="connection-status" class="connection-status disconnected">📡 Connecting to WebSocket monitor...</div><div class="controls"><button id="pause-btn" class="btn">⏸️ Pause feed</button><button id="clear-btn" class="btn secondary">🧹 Clear feed</button><button id="download-btn" class="btn secondary">⬇️ Download JSON</button><div class="filters"><span>Filter:</span><label><input type="checkbox" id="filter-critical" checked /> Critical/High</label><label><input type="checkbox" id="filter-warning" checked /> Medium</label><label><input type="checkbox" id="filter-info" checked /> Info</label></div></div><div class="grid"><div class="card"><h3>📊 Monitoring Overview</h3><div class="metric"><span>Targets Monitored:</span><span class="metric-value" id="target-count">0</span></div><div class="metric"><span>Active Scans:</span><span class="metric-value" id="active-scans">0</span></div><div class="metric"><span>Total Events:</span><span class="metric-value" id="total-events">0</span></div><div class="metric"><span>Critical Alerts:</span><span class="metric-value" id="critical-alerts" style="color:#ef4444;">0</span></div><div class="metric"><span>Connected Clients:</span><span class="metric-value" id="connected-clients">0</span></div><div class="metric"><span>Alerts Queued:</span><span class="metric-value" id="alerts-queued">0</span></div></div><div class="card"><h3>📈 Live Trends</h3><div style="display:grid;gap:1rem;"><div><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.25rem;"><span>Total Findings (last scans)</span><small id="trend-latest" style="color:#9ca3af;">n/a</small></div><canvas id="trendChart" height="120"></canvas></div><div><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.25rem;"><span>Severity Mix</span><small id="mix-latest" style="color:#9ca3af;">n/a</small></div><canvas id="mixChart" height="120"></canvas></div></div></div><div class="card"><h3>🚨 Recent Events</h3><div class="events" id="events"><div class="event info"><div>System initialized</div><div class="timestamp">Waiting for events...</div></div></div></div></div></div><script nonce="__NONCE__">let ws;let eventCount=0;let criticalCount=0;let paused=false;const pendingEvents=[];const capturedEvents=[];const filters={critical:true,warning:true,info:true};let trendChart,mixChart;const trendLabels=[],trendData=[];const mixData={critical:0,high:0,medium:0,low:0,info:0};function initCharts(){const t=document.getElementById('trendChart'),m=document.getElementById('mixChart');if(t){trendChart=new Chart(t,{type:'line',data:{labels:trendLabels,datasets:[{label:'Findings',data:trendData,borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,0.2)',tension:.2,pointRadius:0}]},options:{responsive:true,plugins:{legend:{labels:{color:'#cbd5e1'}}},scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'#1f2937'}},y:{ticks:{color:'#94a3b8'},grid:{color:'#1f2937'}}}}})}if(m){mixChart=new Chart(m,{type:'doughnut',data:{labels:['Critical','High','Medium','Low','Info'],datasets:[{data:[0,0,0,0,0],backgroundColor:['#ef4444','#fb923c','#f59e0b','#22c55e','#3b82f6']}]},options:{plugins:{legend:{labels:{color:'#cbd5e1'}}}}})}}function updateTrend(e){const t=new Date().toLocaleTimeString();trendLabels.push(t),trendData.push(e),trendLabels.length>60&&(trendLabels.shift(),trendData.shift()),trendChart&&trendChart.update('none');const a=document.getElementById('trend-latest');a&&(a.textContent=String(e))}function updateMix(e,t,a,n,o){mixData.critical=e,mixData.high=t,mixData.medium=a,mixData.low=n,mixData.info=o,mixChart&&(mixChart.data.datasets[0].data=[e,t,a,n,o],mixChart.update('none'));const i=document.getElementById('mix-latest');i&&(i.textContent='C:'+e+' H:'+t+' M:'+a+' L:'+n+' I:'+o)}function applyFilters(){const e=document.getElementById('events');e&&Array.from(e.children).forEach(e=>{e.classList&&(e.classList.contains('critical')?e.style.display=filters.critical?'':'none':e.classList.contains('warning')?e.style.display=filters.warning?'':'none':e.classList.contains('info')&&(e.style.display=filters.info?'':'none'))})}async function hydrate(){try{const e=await fetch('http://localhost:${parseInt(options.monitorPort) + 1}/api/status');if(e.ok){const t=await e.json();t&&t.stats&&(document.getElementById('target-count').textContent=t.stats.targets||0,document.getElementById('active-scans').textContent=t.stats.active_scans||0,document.getElementById('connected-clients').textContent=t.stats.connected_clients||0,document.getElementById('alerts-queued').textContent=t.stats.alerts_queued||0)}}catch{}}function connect(){const e='ws://localhost:${options.monitorPort}/ws'+(${options.wsToken ? '"?token=' + encodeURIComponent('${options.wsToken}') + '"' : "''"}),t='ws://localhost:${options.monitorPort}/'+(${options.wsToken ? '"?token=' + encodeURIComponent('${options.wsToken}') + '"' : "''"});let a=false;try{const e=document.getElementById('status');e&&(e.textContent='Connecting to '+primary+' ...')}catch{}ws=new WebSocket(e),ws.onopen=function(){document.getElementById('connection-status').className='connection-status connected',document.getElementById('connection-status').innerHTML='✅ Connected to monitor',document.getElementById('status').textContent='Connected - Receiving live updates'},ws.onclose=function(e){document.getElementById('connection-status').className='connection-status disconnected',document.getElementById('connection-status').innerHTML='❌ Disconnected from monitor'+(e&&e.code?' (code '+e.code+')':''),document.getElementById('status').textContent='Disconnected - Attempting to reconnect...',setTimeout(()=>{a?connect():a=true;try{ws=new WebSocket(t)}catch{}},3e3)},ws.onmessage=function(e){try{const t=JSON.parse(e.data);handleEvent(t)}catch(e){console.error('Failed to parse WebSocket message:',e)}},ws.onerror=function(e){console.error('WebSocket error:',e)}}function handleEvent(e){eventCount++,document.getElementById('total-events').textContent=eventCount,'status'===e.type&&e.data&&(void 0!==e.data.targets&&(document.getElementById('target-count').textContent=e.data.targets),void 0!==e.data.active_scans&&(document.getElementById('active-scans').textContent=e.data.active_scans),void 0!==e.data.connected_clients&&(document.getElementById('connected-clients').textContent=e.data.connected_clients),void 0!==e.data.alerts_queued&&(document.getElementById('alerts-queued').textContent=e.data.alerts_queued)),'metric'===e.type&&e.data&&(void 0!==e.data.active_scans&&(document.getElementById('active-scans').textContent=e.data.active_scans),void 0!==e.data.findings_count&&updateTrend(e.data.findings_count));const t=document.getElementById('events'),a=document.createElement('div');let n='info';('critical'===e.severity||'high'===e.severity)&&(n='critical',criticalCount++,document.getElementById('critical-alerts').textContent=criticalCount),'medium'===e.severity&&(n='warning'),a.className='event '+n,a.innerHTML='\n                <div>'+e.type+': '+(e.message||JSON.stringify(e.data))+'</div>\n                <div class="timestamp">'+new Date(e.timestamp).toLocaleString()+'</div>\n            ',capturedEvents.unshift({type:e.type,severity:e.severity||'info',timestamp:e.timestamp,target:e.target||'system',data:e.data||null}),capturedEvents.length>200&&capturedEvents.pop(),paused?pendingEvents.push(a):(t.insertBefore(a,t.firstChild),applyFilters());for(;t.children.length>50;)t.removeChild(t.lastChild)}hydrate(),connect(),initCharts(),document.getElementById('pause-btn').addEventListener('click',()=>{paused=!paused;const e=document.getElementById('pause-btn');if(paused)e.textContent='▶️ Resume feed',e.classList.add('secondary');else{e.textContent='⏸️ Pause feed',e.classList.remove('secondary');const t=document.getElementById('events');for(;pendingEvents.length;){const e=pendingEvents.shift();t.insertBefore(e,t.firstChild)}applyFilters()}}),document.getElementById('filter-critical').addEventListener('change',e=>{filters.critical=e.target.checked,applyFilters()}),document.getElementById('filter-warning').addEventListener('change',e=>{filters.warning=e.target.checked,applyFilters()}),document.getElementById('filter-info').addEventListener('change',e=>{filters.info=e.target.checked,applyFilters()}),document.getElementById('clear-btn').addEventListener('click',()=>{const e=document.getElementById('events');for(;e.firstChild;)e.removeChild(e.firstChild);capturedEvents.length=0,eventCount=0,criticalCount=0,document.getElementById('total-events').textContent='0',document.getElementById('critical-alerts').textContent='0'}),document.getElementById('download-btn').addEventListener('click',()=>{const e=new Blob([JSON.stringify(capturedEvents,null,2)],{type:'application/json'}),t=URL.createObjectURL(e),a=document.createElement('a');a.href=t,a.download='events-'+new Date().toISOString().replace(/[:.]/g,'-')+'.json',document.body.appendChild(a),a.click(),document.body.removeChild(a),URL.revokeObjectURL(t)})</script></body></html>`;
        const server = http.createServer(async (_req: any, res: any) => {
          try {
            const url = new URL(_req.url || '/', `http://localhost:${options.port}`);
            const nonce = crypto.randomBytes(16).toString('base64');
            const monitorPort = parseInt(options.monitorPort);
            const csp = [
              "default-src 'self'",
              `script-src 'self' 'nonce-${nonce}' https://cdn.jsdelivr.net`,
              `connect-src 'self' ws://localhost:${monitorPort} http://localhost:${monitorPort + 1}`,
              "img-src 'self' data:",
              "style-src 'self' 'unsafe-inline'",
              "font-src 'self'",
              "frame-ancestors 'none'",
              "object-src 'none'",
              "base-uri 'none'",
              "form-action 'none'",
            ].join('; ');
            if (url.pathname === '/api/status') {
              try {
                const target = `http://localhost:${parseInt(options.monitorPort) + 1}/api/status`;
                const headers: any = {};
                const token = options.wsToken || process.env.ZTIS_STATUS_TOKEN || '';
                if (token) headers['x-ztis-token'] = token;
                const resp = await fetch(target, { headers });
                const body = await (resp as any).text();
                res.writeHead((resp as any).status, {
                  'Content-Type': 'application/json',
                  'Cache-Control': 'no-cache',
                  'X-Content-Type-Options': 'nosniff',
                  'Referrer-Policy': 'no-referrer',
                  'X-Frame-Options': 'DENY',
                  'Content-Security-Policy': "default-src 'none'",
                });
                res.end(body);
              } catch (_e) {
                res.writeHead(502, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ ok: false, error: 'Monitor status API unavailable' }));
              }
              return;
            }
            res.writeHead(200, {
              'Content-Type': 'text/html',
              'X-Content-Type-Options': 'nosniff',
              'Referrer-Policy': 'no-referrer',
              'X-Frame-Options': 'DENY',
              'Content-Security-Policy': csp,
              'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            });
            res.end(dashboardHtml.replace(/__NONCE__/g, nonce));
          } catch {
            res.writeHead(500);
            res.end('Server error');
          }
        });
        server.listen(parseInt(options.port), () => {
          console.log(chalk.green('✅ Dashboard server started'));
          console.log(chalk.blue(`🌐 Open your browser to: http://localhost:${options.port}`));
          console.log(chalk.gray('📡 Connecting to monitor on port:'), options.monitorPort);
          console.log(chalk.yellow('🛑 Press Ctrl+C to stop dashboard'));
        });
        const shutdown = () => {
          console.log(chalk.yellow('\n🛑 Shutting down dashboard...'));
          server.close(() => {
            console.log(chalk.green('✅ Dashboard stopped gracefully'));
            process.exit(0);
          });
        };
        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
      } catch (error: any) {
        console.error(chalk.red('❌ Dashboard startup failed:'), error.message);
        process.exit(1);
      }
    });

  program
    .command('config')
    .description('Manage scanner configuration')
    .option('--init', 'Initialize configuration file')
    .option('--validate', 'Validate current configuration')
    .option('--show', 'Show current configuration')
    .action(async (options) => {
      const { ConfigManager } = await import('../config/config-manager');
      const configPath = (program.opts() as any).config as string;
      const mgr = ConfigManager.getInstance();
      if (options.init) {
        console.log(chalk.blue('📝 Initializing configuration...'));
        await mgr.initialize(configPath);
        await mgr.createDefaultConfig(configPath);
        console.log(chalk.green(`✅ Configuration file created: ${configPath}`));
      } else if (options.validate) {
        console.log(chalk.blue('🔍 Validating configuration...'));
        await mgr.initialize(configPath);
        const validation = mgr.validateConfig();
        if (!validation.valid) {
          console.error(chalk.red('❌ Configuration validation failed:'));
          (validation.errors || []).forEach((e) => console.error('  -', e));
          process.exit(1);
        }
        console.log(chalk.green('✅ Configuration is valid'));
      } else if (options.show) {
        console.log(chalk.blue('📋 Current configuration:'));
        await mgr.initialize(configPath);
        const cfg = mgr.getConfig();
        const outFmt = (program.opts() as any).output as string;
        if (outFmt === 'yaml' || outFmt === 'yml') {
          const { stringify } = await import('yaml');
          console.log(stringify(cfg));
        } else {
          console.log(JSON.stringify(cfg, null, 2));
        }
      } else {
        console.log(chalk.red('❌ Please specify an action (--init, --validate, or --show)'));
      }
    });

  program
    .command('server')
    .description('Start the Zero-Trust Scanner web dashboard')
    .option('-p, --port <port>', 'Server port', '3000')
    .option('-h, --host <host>', 'Server host', 'localhost')
    .option('--api-only', 'Start API server without web interface')
    .action(async (options) => {
      console.log(chalk.blue('🚀 Starting Zero-Trust Scanner Server'));
      console.log(chalk.gray('URL:'), `http://${options.host}:${options.port}`);
      console.log(chalk.yellow('⚠️  Web server coming soon...'));
    });
};

export default registerMonitorCommands;
