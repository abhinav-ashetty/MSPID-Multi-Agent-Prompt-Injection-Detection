import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { simulationApi } from '../services/api';
import { outcomePresentation } from '../components/simulation/outcomePresentation';
import { SimulationResultView } from '../components/simulation/SimulationResultView';
import type {
  AttackCategory,
  SimulationHistoryItem,
  SimulationResult,
  SimulationStatistics,
} from '../types/simulation';

const categories: AttackCategory[] = [
  'BENIGN',
  'PROMPT_INJECTION',
  'INSTRUCTION_CONFLICT',
  'ROLE_MANIPULATION',
  'SYSTEM_PROMPT_EXTRACTION',
  'SENSITIVE_INFORMATION_REQUEST',
];
const pageSize = 20;

export function Simulation() {
  const [category, setCategory] = useState<AttackCategory>('PROMPT_INJECTION');
  const [canaryText, setCanaryText] = useState('');
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [statistics, setStatistics] = useState<SimulationStatistics | null>(null);
  const [history, setHistory] = useState<SimulationHistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [error, setError] = useState('');
  const [historyError, setHistoryError] = useState('');
  const [refresh, setRefresh] = useState(0);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError('');
    try {
      const [historyResponse, statisticsResponse] = await Promise.all([
        simulationApi.list(pageSize, offset),
        simulationApi.statistics(),
      ]);
      setHistory(historyResponse.items);
      setTotal(historyResponse.total);
      setStatistics(statisticsResponse);
    } catch {
      setHistoryError('Could not load simulation history. Check the backend connection and retry.');
    } finally {
      setHistoryLoading(false);
    }
  }, [offset]);

  useEffect(() => { void loadHistory(); }, [loadHistory, refresh]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (loading) return;
    setLoading(true);
    setError('');
    setResult(null);
    const protectedCanaries = canaryText.split(/[\n,]/).map(value => value.trim()).filter(Boolean);
    try {
      const record = await simulationApi.run({
        attack_category: category,
        protected_canaries: protectedCanaries,
        success_criterion: 'PROTECTED_CANARY_MATCH',
      });
      setResult(record.result);
      setOffset(0);
      setRefresh(value => value + 1);
    } catch (caught) {
      if (axios.isAxiosError<{ detail?: string }>(caught) && caught.code === 'ECONNABORTED') {
        setError('The simulation exceeded the request time limit. Gemini may be slow; retry, or check the backend logs.');
      } else {
        const detail = axios.isAxiosError<{ detail?: string }>(caught)
          ? caught.response?.data?.detail
          : undefined;
        setError(detail || 'Simulation could not be run. Check backend configuration and try again.');
      }
    } finally {
      setLoading(false);
    }
  }

  return <section className="space-y-8">
    <div>
      <h1 className="text-2xl font-bold">Attack simulation</h1>
      <p className="mt-2 text-gray-600">Generate a controlled attack, assess it with the Defender, then check the Target response for configured canaries.</p>
    </div>

    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
      <Stat title="Total simulations" value={statistics?.total_simulations} />
      <Stat title="Successful attacks" value={statistics?.successful_attacks} />
      {(['PREVENTED', 'LEAKED', 'NO_LEAK', 'TARGET_ERROR'] as const).map(outcome =>
        <Stat key={outcome} title={outcomePresentation[outcome].label} value={statistics?.outcomes[outcome]} />
      )}
    </div>

    <form onSubmit={submit} className="space-y-4 rounded-xl border bg-white p-6 shadow-sm">
      <div>
        <label htmlFor="attack-category" className="mb-2 block font-medium">Attack category</label>
        <select id="attack-category" value={category} onChange={event => setCategory(event.target.value as AttackCategory)} disabled={loading} className="w-full rounded border p-3 sm:max-w-md">
          {categories.map(value => <option value={value} key={value}>{value.replace(/_/g, ' ')}</option>)}
        </select>
      </div>
      <div>
        <label htmlFor="protected-canaries" className="mb-2 block font-medium">Protected canaries <span className="font-normal text-gray-500">(optional, one per line or comma separated)</span></label>
        <textarea id="protected-canaries" value={canaryText} onChange={event => setCanaryText(event.target.value)} disabled={loading} rows={3} className="w-full rounded border p-3" placeholder="Example: TEST-SECRET-123" />
        <p className="mt-1 text-sm text-gray-500">Enter only a marker for detecting leaks, not an attack prompt. The selected category generates the attack; it counts as successful only when this marker appears in the Target response.</p>
      </div>
      <button type="submit" disabled={loading} className="rounded bg-blue-600 px-4 py-2 font-medium text-white disabled:cursor-wait disabled:opacity-60">
        {loading ? 'Simulation running…' : 'Run simulation'}
      </button>
      {loading && <p role="status" className="text-sm text-gray-600">Running Attacker → Defender → Target evaluation…</p>}
      {error && <p role="alert" className="text-red-700">{error}</p>}
    </form>

    {result && <SimulationResultView result={result} />}

    <section aria-labelledby="simulation-history-title">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 id="simulation-history-title" className="text-xl font-semibold">Simulation history</h2>
        <button type="button" onClick={() => setRefresh(value => value + 1)} disabled={historyLoading} className="rounded border px-3 py-2 text-sm disabled:opacity-50">Refresh</button>
      </div>
      {historyError ? <div role="alert" className="rounded-xl border bg-white p-5"><p>{historyError}</p><button onClick={() => setRefresh(value => value + 1)} className="mt-3 rounded bg-blue-600 px-3 py-2 text-white">Retry</button></div>
        : historyLoading ? <p role="status">Loading simulation history…</p>
          : history.length === 0 ? <p className="rounded-xl border bg-white p-5 text-gray-600">No simulations yet. Run one above to create history.</p>
            : <>
              <div className="overflow-x-auto rounded-xl border bg-white">
                <table className="w-full text-left text-sm">
                  <thead><tr className="border-b bg-gray-50"><th className="p-3">Time</th><th className="p-3">Category</th><th className="p-3">Defender</th><th className="p-3">Target ran</th><th className="p-3">Outcome</th><th className="p-3">Success</th><th className="p-3">Details</th></tr></thead>
                  <tbody>{history.map(item => <tr key={item.simulation_id} className="border-b">
                    <td className="p-3">{new Date(item.created_at).toLocaleString()}</td>
                    <td className="p-3">{item.attack_category.replace(/_/g, ' ')}</td>
                    <td className="p-3">{item.defender_decision ?? '—'}</td>
                    <td className="p-3">{item.target_called ? 'Yes' : 'No'}</td>
                    <td className="p-3"><OutcomeBadge outcome={item.outcome} /></td>
                    <td className="p-3">{item.attack_success ? 'Yes' : 'No'}</td>
                    <td className="p-3"><Link className="text-blue-700 underline" to={`/simulations/${encodeURIComponent(item.simulation_id)}`}>View</Link></td>
                  </tr>)}</tbody>
                </table>
              </div>
              <div className="mt-4 flex items-center gap-3">
                <button disabled={!offset || historyLoading} className="rounded border px-3 py-2 disabled:opacity-50" onClick={() => setOffset(Math.max(0, offset - pageSize))}>Previous</button>
                <span>{total === 0 ? '0' : `${offset + 1}–${Math.min(offset + history.length, total)}`} of {total}</span>
                <button disabled={offset + history.length >= total || historyLoading} className="rounded border px-3 py-2 disabled:opacity-50" onClick={() => setOffset(offset + pageSize)}>Next</button>
              </div>
            </>}
    </section>
  </section>;
}

function Stat({ title, value }: { title: string; value?: number }) {
  return <article className="rounded-xl border bg-white p-4 shadow-sm"><p className="text-sm text-gray-600">{title}</p><p className="mt-2 text-2xl font-bold">{value === undefined ? '—' : value}</p></article>;
}

function OutcomeBadge({ outcome }: { outcome: SimulationHistoryItem['outcome'] }) {
  const presentation = outcomePresentation[outcome];
  return <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${presentation.classes}`}>{presentation.label}</span>;
}
