import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { simulationApi } from '../services/api';
import { SimulationResultView } from '../components/simulation/SimulationResultView';
import type { SimulationRunRecord } from '../types/simulation';

export function SimulationDetails() {
  const { simulationId } = useParams();
  const [record, setRecord] = useState<SimulationRunRecord | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    if (!simulationId) { setError('Invalid simulation ID.'); return; }
    simulationApi.get(simulationId)
      .then(value => { if (active) setRecord(value); })
      .catch(() => { if (active) setError('Simulation details could not be loaded. Check the backend connection.'); });
    return () => { active = false; };
  }, [simulationId]);

  return <section>
    <Link to="/simulations" className="mb-5 inline-block text-blue-700 underline">← Simulation history</Link>
    {error ? <div role="alert" className="rounded-xl border bg-white p-5"><p>{error}</p><Link className="mt-3 inline-block text-blue-700 underline" to="/simulations">Back to simulations</Link></div>
      : !record ? <p role="status">Loading simulation…</p>
        : <div className="space-y-4"><p className="text-sm text-gray-500">Run #{record.id} · {new Date(record.created_at).toLocaleString()}</p><SimulationResultView result={record.result} title="Simulation details" /></div>}
  </section>;
}
