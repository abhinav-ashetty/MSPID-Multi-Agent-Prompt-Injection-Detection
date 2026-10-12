import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { securityApi } from '../services/api';
import type { AssessmentItem } from '../types/security';

export function Assessments() {
  const [items, setItems] = useState<AssessmentItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState('');
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let active = true;
    securityApi.getAssessments(20, offset).then(data => { if (active) { setItems(data.items); setTotal(data.total); setError(''); } })
      .catch(() => { if (active) setError('Could not load assessments. Check the backend connection.'); });
    return () => { active = false; };
  }, [offset, reload]);
  return <section><h1 className="mb-6 text-2xl font-bold">Assessment history</h1>
    {error ? <div role="alert"><p>{error}</p><button className="mt-3 rounded bg-blue-600 px-4 py-2 text-white" onClick={() => setReload(x => x + 1)}>Retry</button></div> : items.length === 0 ? <p>No assessments yet. <Link className="text-blue-700 underline" to="/analyze">Analyze a prompt</Link>.</p> : <>
      <div className="overflow-x-auto rounded-xl border bg-white"><table className="w-full text-left text-sm"><thead><tr className="border-b bg-gray-50"><th className="p-3">ID</th><th className="p-3">Time</th><th className="p-3">Risk</th><th className="p-3">Decision</th><th className="p-3">Type</th></tr></thead><tbody>{items.map(item => <tr key={item.id} className="border-b"><td className="p-3"><Link className="text-blue-700 underline" to={`/assessments/${item.id}`}>#{item.id}</Link></td><td className="p-3">{new Date(item.timestamp).toLocaleString()}</td><td className="p-3">{item.final_risk_score}</td><td className="p-3">{item.decision}</td><td className="p-3">{item.attack_type}</td></tr>)}</tbody></table></div>
      <div className="mt-4 flex items-center gap-3"><button disabled={!offset} className="rounded border px-3 py-2 disabled:opacity-50" onClick={() => setOffset(Math.max(0, offset - 20))}>Previous</button><span>{offset + 1}–{Math.min(offset + items.length, total)} of {total}</span><button disabled={offset + items.length >= total} className="rounded border px-3 py-2 disabled:opacity-50" onClick={() => setOffset(offset + 20)}>Next</button></div>
    </>}</section>;
}
