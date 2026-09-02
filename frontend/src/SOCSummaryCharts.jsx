import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';

const VERDICTS_DATA = [
  { name: 'Mon', malicious: 4, clean: 24 },
  { name: 'Tue', malicious: 7, clean: 30 },
  { name: 'Wed', malicious: 3, clean: 22 },
  { name: 'Thu', malicious: 12, clean: 28 },
  { name: 'Fri', malicious: 5, clean: 15 },
  { name: 'Sat', malicious: 2, clean: 8 },
  { name: 'Sun', malicious: 1, clean: 5 },
];

const TERMS_DATA = [
  { name: 'Password Reset', count: 45 },
  { name: 'Urgent Action', count: 32 },
  { name: 'Invoice attached', count: 28 },
  { name: 'Account Suspended', count: 20 },
  { name: 'Wire Transfer', count: 15 },
];

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: 'var(--panel-bg)',
        border: '1px solid var(--panel-border)',
        padding: '12px',
        borderRadius: '8px',
        backdropFilter: 'blur(8px)',
        color: 'var(--text-primary)'
      }}>
        <p style={{ margin: '0 0 8px 0', fontWeight: 'bold' }}>{label}</p>
        {payload.map((entry, index) => (
          <p key={`item-${index}`} style={{ margin: '4px 0', color: entry.color }}>
            {entry.name}: {entry.value}
          </p>
        ))}
      </div>
    );
  }
  return null;
};

const SOCSummaryCharts = () => {
  return (
    <div className="charts-grid">
      <div className="glass-panel" style={{ height: '350px', display: 'flex', flexDirection: 'column' }}>
        <h3 className="chart-title">Verdicts Over Time (7 Days)</h3>
        <div style={{ flex: 1, minHeight: 0 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={VERDICTS_DATA} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorClean" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#22c55e" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" vertical={false} />
              <XAxis dataKey="name" stroke="var(--text-secondary)" tick={{fontSize: 12}} axisLine={false} tickLine={false} />
              <YAxis stroke="var(--text-secondary)" tick={{fontSize: 12}} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="malicious" stroke="#ef4444" strokeWidth={3} fillOpacity={1} fill="url(#colorMalicious)" name="Malicious" />
              <Area type="monotone" dataKey="clean" stroke="#22c55e" strokeWidth={3} fillOpacity={1} fill="url(#colorClean)" name="Clean" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="glass-panel" style={{ height: '350px', display: 'flex', flexDirection: 'column' }}>
        <h3 className="chart-title">Top Flagged Terms</h3>
        <div style={{ flex: 1, minHeight: 0 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={TERMS_DATA} layout="vertical" margin={{ top: 10, right: 10, left: 20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" horizontal={false} />
              <XAxis type="number" stroke="var(--text-secondary)" tick={{fontSize: 12}} axisLine={false} tickLine={false} />
              <YAxis dataKey="name" type="category" stroke="var(--text-primary)" tick={{fontSize: 12}} axisLine={false} tickLine={false} width={120} />
              <Tooltip content={<CustomTooltip />} cursor={{fill: 'rgba(255,255,255,0.05)'}} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]} name="Occurrences">
                {TERMS_DATA.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={index === 0 ? '#f97316' : '#3b82f6'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default SOCSummaryCharts;
