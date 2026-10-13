import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import { securityApi } from '../services/api';
import type { SecurityAnalysisResponse } from '../types/security';

export function AssessmentDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [item, setItem] = useState<SecurityAnalysisResponse | null>(null);
  const [error, setError] = useState('');
  const [reanalyzing, setReanalyzing] = useState(false);
  const [useGemini, setUseGemini] = useState(true);

  useEffect(() => {
    let active = true;
    if (!id || !/^\d+$/.test(id)) { setError('Invalid assessment ID.'); return; }
    securityApi.getAssessment(Number(id)).then(value => { if (active) setItem(value); })
      .catch(() => { if (active) setError('Assessment could not be loaded.'); });
    return () => { active = false; };
  }, [id]);

  async function reanalyze() {
    if (!item || reanalyzing) return;
    setReanalyzing(true);
    setError('');
    try {
      const updated = await securityApi.analyzePrompt({
        prompt: item.prompt,
        use_gemini: useGemini,
      });
      setItem(updated);
      navigate(`/assessments/${updated.id}`, { replace: true });
    } catch (caught) {
      const detail = axios.isAxiosError<{ detail?: string }>(caught)
        ? caught.response?.data?.detail
        : undefined;
      setError(detail || 'Re-analysis failed. Confirm the backend is running and configured, then try again.');
    } finally {
      setReanalyzing(false);
    }
  }

  if (error && !item) return <section role="alert"><p>{error}</p><Link to="/assessments" className="text-blue-700 underline">Back to assessments</Link></section>;
  if (!item) return <p role="status">Loading assessment…</p>;
  return <section>
    <Link to="/assessments" className="text-blue-700 underline">← Assessment history</Link>
    <h1 className="my-5 text-2xl font-bold">Assessment #{item.id}</h1>
    <article className="space-y-4 rounded-xl border bg-white p-6">
      <p><strong>Decision:</strong> {item.decision}</p>
      <p><strong>Risk:</strong> {item.final_risk_score}/100</p>
      <p><strong>Attack type:</strong> {item.attack_type}</p>
      <p><strong>Confidence:</strong> {(item.confidence * 100).toFixed(0)}%</p>
      <p><strong>Rule score:</strong> {item.rule_score}<span className="ml-2 text-sm text-gray-600">(matched rule signals; 0 means none matched)</span></p>
      <p><strong>ML signal:</strong> {(item.ml_probability * 100).toFixed(0)}%</p>
      <p><strong>Gemini:</strong> {item.gemini_used ? `${item.gemini_risk_score}/100` : 'Not used'}{item.gemini_used && <span className="ml-2 text-sm text-gray-600">(Gemini’s estimated prompt risk)</span>}</p>
      <p><strong>Reason:</strong> {item.reason}</p>
      <p><strong>Prompt:</strong></p>
      <pre className="whitespace-pre-wrap break-words rounded bg-gray-50 p-4">{item.prompt}</pre>
      <div className="border-t pt-4">
        <label className="mb-3 flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={useGemini}
            onChange={event => setUseGemini(event.target.checked)}
            disabled={reanalyzing}
            className="mt-0.5"
          />
          <span>
            <span className="block font-medium">Use Gemini for re-analysis</span>
            <span className="text-gray-600">
              {useGemini
                ? 'Includes Gemini analysis and uses your API quota.'
                : 'Off: use only local rule-based and ML detectors.'}
            </span>
          </span>
        </label>
        <button type="button" onClick={reanalyze} disabled={reanalyzing} className="rounded bg-blue-600 px-4 py-2 font-medium text-white disabled:cursor-wait disabled:opacity-60">
          {reanalyzing ? 'Analyzing…' : 'Re-analyze'}
        </button>
        <p className="mt-2 text-sm text-gray-600">This creates a new history entry using the selected analysis mode.</p>
        {error && <p role="alert" className="mt-2 text-sm text-red-700">{error}</p>}
      </div>
    </article>
  </section>;
}
