import type { SimulationResult } from '../../types/simulation';
import { outcomePresentation } from './outcomePresentation';

interface Props {
  result: SimulationResult;
  title?: string;
}

export function SimulationResultView({ result, title = 'Simulation result' }: Props) {
  const outcome = outcomePresentation[result.outcome];
  const riskScore = result.defender_assessment?.final_risk_score;

  return <section aria-label={title} className="rounded-xl border bg-white p-6 shadow-sm">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h2 className="text-xl font-semibold">{title}</h2>
      <span role="status" className={`rounded-full px-3 py-1 text-sm font-semibold ${outcome.classes}`}>
        {outcome.label}
      </span>
    </div>

    <dl className="mt-5 grid gap-4 sm:grid-cols-2">
      <div><dt className="text-sm text-gray-500">Attack category</dt><dd className="font-medium">{result.attack?.category ?? 'Unavailable'}</dd></div>
      <div><dt className="text-sm text-gray-500">Defender decision</dt><dd className="font-medium">{result.defender_decision ?? 'Unavailable'}</dd></div>
      <div><dt className="text-sm text-gray-500">Defender risk score</dt><dd className="font-medium">{riskScore === undefined ? 'Unavailable' : `${riskScore}/100`}</dd></div>
      <div><dt className="text-sm text-gray-500">Target executed</dt><dd className="font-medium">{result.target_called ? 'Yes' : 'No'}</dd></div>
      <div><dt className="text-sm text-gray-500">Attack success</dt><dd className="font-medium">{result.attack_success ? 'Yes' : 'No'}</dd></div>
      <div><dt className="text-sm text-gray-500">Simulation ID</dt><dd className="break-all font-medium">{result.simulation_id}</dd></div>
    </dl>

    {result.defender_decision === 'SANITIZE' && <p role="note" className="mt-4 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950">
      SANITIZE is not implemented. The original prompt was passed to the Target unchanged.
    </p>}
    {result.outcome === 'PREVENTED' && <p className="mt-4 text-sm text-blue-800">The Defender blocked the prompt, so the Target was not executed.</p>}

    <div className="mt-5">
      <h3 className="font-semibold">Generated attack prompt</h3>
      {result.attack ? <pre className="mt-2 whitespace-pre-wrap break-words rounded-lg bg-gray-50 p-4 text-sm">{result.attack.prompt}</pre> : <p className="mt-2 text-sm text-gray-600">No valid attack prompt was generated.</p>}
    </div>

    <div className="mt-5">
      <h3 className="font-semibold">Leakage matches</h3>
      {result.leakage_matches.length ? <ul className="mt-2 list-inside list-disc space-y-1 text-sm">
        {result.leakage_matches.map((match, index) => <li key={`${match.canary}-${index}`}><code>{match.canary}</code> ({match.match_type.toLowerCase()} match)</li>)}
      </ul> : <p className="mt-2 text-sm text-gray-600">No configured canary matched.</p>}
    </div>

    {result.target_response && <div className="mt-5">
      <h3 className="font-semibold">Target response · {result.target_response.target_name}</h3>
      <pre className="mt-2 whitespace-pre-wrap break-words rounded-lg bg-gray-50 p-4 text-sm">{result.target_response.response}</pre>
    </div>}

    {result.error && <p role="alert" className="mt-4 rounded-lg bg-amber-50 p-3 text-sm text-amber-900">{result.error}</p>}
    {result.failed_stage && <p className="mt-2 text-sm text-gray-600">Failed stage: {result.failed_stage}</p>}
  </section>;
}
