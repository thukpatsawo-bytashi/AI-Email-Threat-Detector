import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';

const INITIAL_VERDICTS = [
  { name: 'Mon', malicious: 0, clean: 0 },
  { name: 'Tue', malicious: 0, clean: 0 },
  { name: 'Wed', malicious: 0, clean: 0 },
  { name: 'Thu', malicious: 0, clean: 0 },
  { name: 'Fri', malicious: 0, clean: 0 },
  { name: 'Sat', malicious: 0, clean: 0 },
  { name: 'Sun', malicious: 0, clean: 0 },
];

const INITIAL_TERMS = [];

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: 'rgba(13, 17, 23, 0.95)',
        border: '1px solid rgba(255, 255, 255, 0.1)',
        padding: '12px 16px',
        borderRadius: '10px',
        backdropFilter: 'blur(12px)',
        color: '#f0f4f8',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
        fontSize: '0.85rem',
      }}>
        <p style={{ margin: '0 0 6px 0', fontWeight: 700, fontSize: '0.9rem' }}>{label}</p>
        {payload.map((entry, index) => (
          <div key={`item-${index}`} style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            margin: '3px 0',
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: entry.color,
              boxShadow: `0 0 4px ${entry.color}60`,
            }} />
            <span style={{ color: '#8b99ae' }}>{entry.name}:</span>
            <span style={{ fontWeight: 600 }}>{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

const SOCSummaryCharts = ({ refreshTrigger }) => {
  const [verdictsData, setVerdictsData] = useState(INITIAL_VERDICTS);
  const [termsData, setTermsData] = useState(INITIAL_TERMS);

  useEffect(() => {
    async function loadCharts() {
      try {
        let res;
        try {
          res = await fetch('/api/stats/charts');
        } catch {
          res = await fetch('http://localhost:8000/api/stats/charts');
        }
        if (res.ok) {
          const data = await res.json();
          if (data.verdicts_over_time && data.verdicts_over_time.length > 0) {
            setVerdictsData(data.verdicts_over_time);
          }
          if (data.top_terms && data.top_terms.length > 0) {
            setTermsData(data.top_terms);
          }
        }
      } catch (err) {
        console.warn('Could not load live charts data:', err);
      }
    }
    loadCharts();
  }, [refreshTrigger]);

  return (
    <div className="charts-grid">
      <div className="glass-panel" style={{
        height: '380px',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        overflow: 'hidden',
      }}>
        {/* Top accent line */}
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '2px',
          background: 'linear-gradient(90deg, transparent, #6366f1, transparent)',
          opacity: 0.5,
        }} />
        <h3 className="chart-title">Verdicts Over Time (7 Days)</h3>
        <div style={{
          display: 'flex',
          gap: '16px',
          marginBottom: '16px',
          fontSize: '0.78rem',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#ef4444' }} />
            <span style={{ color: 'var(--text-muted)' }}>Malicious</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#22c55e' }} />
            <span style={{ color: 'var(--text-muted)' }}>Clean</span>
          </div>
        </div>
        <div style={{ flex: 1, minHeight: 0 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={verdictsData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25}/>
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorClean" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22c55e" stopOpacity={0.25}/>
                  <stop offset="95%" stopColor="#22c55e" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis
                dataKey="name"
                stroke="rgba(255,255,255,0.15)"
                tick={{ fontSize: 12, fill: '#556378' }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                stroke="rgba(255,255,255,0.15)"
                tick={{ fontSize: 12, fill: '#556378' }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area
                type="monotone"
                dataKey="malicious"
                stroke="#ef4444"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#colorMalicious)"
                name="Malicious"
                dot={{ r: 3, fill: '#ef4444', strokeWidth: 0 }}
                activeDot={{ r: 5, stroke: '#ef4444', strokeWidth: 2, fill: '#0d1117' }}
              />
              <Area
                type="monotone"
                dataKey="clean"
                stroke="#22c55e"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#colorClean)"
                name="Clean"
                dot={{ r: 3, fill: '#22c55e', strokeWidth: 0 }}
                activeDot={{ r: 5, stroke: '#22c55e', strokeWidth: 2, fill: '#0d1117' }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="glass-panel" style={{
        height: '380px',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        overflow: 'hidden',
      }}>
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '2px',
          background: 'linear-gradient(90deg, transparent, #f97316, transparent)',
          opacity: 0.5,
        }} />
        <h3 className="chart-title">Top Flagged Terms</h3>
        <div style={{ flex: 1, minHeight: 0 }}>
          {termsData.length === 0 ? (
              <div style={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--text-muted)',
                fontSize: '0.85rem',
                textAlign: 'center',
                padding: '24px',
              }}>
                <div>No indicators logged yet.</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Analyze an email above to generate live keyword metrics.
                </div>
              </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={termsData} layout="vertical" margin={{ top: 10, right: 20, left: 20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false} />
                <XAxis
                  type="number"
                  stroke="rgba(255,255,255,0.15)"
                  tick={{ fontSize: 12, fill: '#556378' }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  dataKey="name"
                  type="category"
                  stroke="rgba(255,255,255,0.15)"
                  tick={{ fontSize: 12, fill: '#8b99ae' }}
                  axisLine={false}
                  tickLine={false}
                  width={130}
                />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.02)' }} />
                <Bar dataKey="count" radius={[0, 6, 6, 0]} name="Occurrences" barSize={22}>
                  {termsData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill || '#6366f1'} fillOpacity={0.8} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
};

export default SOCSummaryCharts;
