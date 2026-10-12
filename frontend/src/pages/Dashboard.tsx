import { useEffect, useState } from 'react';
import { ShieldCheck, CheckCircle, Repeat, XCircle } from 'lucide-react';
import { securityApi } from '../services/api';
import type { StatisticsResponse } from '../types/security';
import { StatCard } from '../components/dashboard/StatCard';
import { SecurityTimeline } from '../components/dashboard/SecurityTimeline';
import { AttackCategories } from '../components/dashboard/AttackCategories';
import { RiskDistribution } from '../components/dashboard/RiskDistribution';
import { RecentAssessments } from '../components/dashboard/RecentAssessments';

export function Dashboard() {
  const [stats, setStats] = useState<StatisticsResponse | null>(null);
  const [error, setError] = useState('');
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let active = true;
    securityApi.getStatistics().then(value => { if (active) { setStats(value); setError(''); } })
      .catch(() => { if (active) setError('Could not reach the security API. Check that the backend is running.'); });
    return () => { active = false; };
  }, [reload]);
  if (error) return <section role="alert" className="rounded-xl bg-white p-6"><p>{error}</p><button className="mt-3 rounded bg-blue-600 px-4 py-2 text-white" onClick={() => setReload(x => x + 1)}>Retry</button></section>;
  if (!stats) return <p role="status">Loading dashboard…</p>;
  return <>
    <h1 className="mb-6 text-2xl font-bold">Security dashboard</h1>
    <div className="mb-8 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
      <StatCard title="Total prompts" value={stats.total_assessments} icon={ShieldCheck} variant="blue" />
      <StatCard title="Allowed" value={stats.decisions.ALLOW} icon={CheckCircle} variant="green" />
      <StatCard title="Sanitized" value={stats.decisions.SANITIZE} icon={Repeat} variant="yellow" />
      <StatCard title="Blocked" value={stats.decisions.BLOCK} icon={XCircle} variant="red" />
    </div>
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3"><div className="xl:col-span-2"><SecurityTimeline /></div><div className="space-y-6"><AttackCategories /><RiskDistribution /></div><div className="xl:col-span-3"><RecentAssessments /></div></div>
  </>;
}
